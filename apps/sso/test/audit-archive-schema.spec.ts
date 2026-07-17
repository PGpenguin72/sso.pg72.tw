import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import {
  AUDIT_ARCHIVE_CONTENT_TYPE,
  AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
  encodeCanonicalAuditRecordsV1,
  sealAuditArchiveV1,
  type AuditArchiveManifestV1,
  type AuditArchiveRecordV1,
} from "../worker/audit-archive-crypto";

const START = Date.parse("2026-07-18T02:00:00.000Z");
const KEK_VERSION = "v1";
const ZERO_KEK = "A".repeat(43);

interface SourceRow {
  actor_ref: string | null;
  actor_ref_hash_version: 1 | null;
  actor_user_id: string | null;
  client_id: string | null;
  event_id: string;
  event_type: string;
  ip_hash: string | null;
  metadata_json: string | null;
  occurred_at: string;
  outcome: "denied" | "failure" | "success";
  sequence: number;
  session_id: string | null;
  subject_id: string | null;
  user_agent_hash: string | null;
}

interface BatchBuild {
  batchKey: string;
  envelope: Uint8Array<ArrayBuffer>;
  itemInsert: D1PreparedStatement;
  manifest: AuditArchiveManifestV1;
  parentInsert: D1PreparedStatement;
  records: AuditArchiveRecordV1[];
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

async function insertAuditEvent(
  index: number,
  options: {
    actorRef?: string | null;
    eventId?: string;
    occurredAt?: string;
  } = {},
): Promise<{ eventId: string; sequence: number }> {
  const eventId = options.eventId ?? crypto.randomUUID();
  const occurredAt = options.occurredAt ?? at(index * 1_000);
  const actorRef = options.actorRef === undefined ? reference(index + 1) : options.actorRef;
  await env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, subject_id, client_id, session_id,
       outcome, ip_hash, user_agent_hash, metadata_json, occurred_at,
       actor_ref, actor_ref_hash_version)
     VALUES (?, 'test.archive', NULL, ?, NULL, NULL,
             'success', NULL, NULL, ?, ?, ?, ?)`,
  )
    .bind(
      eventId,
      `subject:${index}`,
      JSON.stringify({ kind: "archive_test", ordinal: index }),
      occurredAt,
      actorRef,
      actorRef === null ? null : 1,
    )
    .run();
  const sequence = await env.PG72_ID_DB.prepare(
    "SELECT sequence FROM audit_archive_source WHERE event_id = ?",
  )
    .bind(eventId)
    .first<number>("sequence");
  if (sequence === null) throw new Error("audit source capture failed");
  return { eventId, sequence };
}

async function outstandingRecords(): Promise<AuditArchiveRecordV1[]> {
  const checkpoint = await env.PG72_ID_DB.prepare(
    "SELECT last_sequence FROM audit_archive_checkpoint WHERE id = 1",
  ).first<number>("last_sequence");
  if (checkpoint === null) throw new Error("missing archive checkpoint");
  const rows = await env.PG72_ID_DB.prepare(
    `SELECT source.sequence, event.id AS event_id, event.event_type,
            event.actor_user_id, event.actor_ref, event.actor_ref_hash_version,
            event.subject_id, event.client_id, event.session_id, event.outcome,
            event.ip_hash, event.user_agent_hash, event.metadata_json,
            event.occurred_at
       FROM audit_archive_source AS source
       JOIN audit_event AS event ON event.id = source.event_id
      WHERE source.sequence > ?
      ORDER BY source.sequence`,
  )
    .bind(checkpoint)
    .all<SourceRow>();
  return rows.results.map((row) => ({
    actorRef: row.actor_ref,
    actorRefHashVersion: row.actor_ref_hash_version,
    actorUserId: row.actor_user_id,
    clientId: row.client_id,
    eventId: row.event_id,
    eventType: row.event_type,
    ipHash: row.ip_hash,
    metadataJson: row.metadata_json,
    occurredAt: row.occurred_at,
    outcome: row.outcome,
    sequence: row.sequence,
    sessionId: row.session_id,
    subjectId: row.subject_id,
    userAgentHash: row.user_agent_hash,
  }));
}

async function installSentinel(createdAt: string): Promise<void> {
  const existing = await env.PG72_ID_DB.prepare(
    `SELECT fingerprint_ref FROM audit_archive_key_sentinel
      WHERE key_version = ?`,
  )
    .bind(KEK_VERSION)
    .first<string>("fingerprint_ref");
  if (existing !== null) {
    expect(existing).toBe(reference(91));
    return;
  }
  await env.PG72_ID_DB.prepare(
    `INSERT INTO audit_archive_key_sentinel
      (key_version, domain, fingerprint_ref, fingerprint_hash_version, created_at)
     VALUES (?, 'pgid.audit_archive_kek_fingerprint.v1', ?, 1, ?)`,
  )
    .bind(KEK_VERSION, reference(91), createdAt)
    .run();
}

const itemInsertSql = `INSERT INTO audit_archive_batch_item
  (batch_key, ordinal, source_sequence, event_id, event_type,
   actor_user_id, actor_ref, actor_ref_hash_version, subject_id,
   client_id, session_id, outcome, ip_hash, user_agent_hash,
   metadata_json, occurred_at, canonical_record_json, canonical_record_bytes)
 SELECT ?, CAST(entry.key AS INTEGER) + 1,
        json_extract(entry.value, '$.sequence'),
        json_extract(entry.value, '$.eventId'),
        json_extract(entry.value, '$.eventType'),
        json_extract(entry.value, '$.actorUserId'),
        json_extract(entry.value, '$.actorRef'),
        json_extract(entry.value, '$.actorRefHashVersion'),
        json_extract(entry.value, '$.subjectId'),
        json_extract(entry.value, '$.clientId'),
        json_extract(entry.value, '$.sessionId'),
        json_extract(entry.value, '$.outcome'),
        json_extract(entry.value, '$.ipHash'),
        json_extract(entry.value, '$.userAgentHash'),
        json_extract(entry.value, '$.metadataJson'),
        json_extract(entry.value, '$.occurredAt'),
        entry.value,
        length(CAST(entry.value AS blob))
   FROM json_each(?) AS entry`;

const singleItemInsertSql = `INSERT INTO audit_archive_batch_item
  (batch_key, ordinal, source_sequence, event_id, event_type,
   actor_user_id, actor_ref, actor_ref_hash_version, subject_id,
   client_id, session_id, outcome, ip_hash, user_agent_hash,
   metadata_json, occurred_at, canonical_record_json, canonical_record_bytes)
 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

function prepareSingleItemInsert(
  batchKey: string,
  ordinal: number,
  record: AuditArchiveRecordV1,
): D1PreparedStatement {
  const canonicalRecord = JSON.stringify(record);
  return env.PG72_ID_DB.prepare(singleItemInsertSql).bind(
    batchKey,
    ordinal,
    record.sequence,
    record.eventId,
    record.eventType,
    record.actorUserId,
    record.actorRef,
    record.actorRefHashVersion,
    record.subjectId,
    record.clientId,
    record.sessionId,
    record.outcome,
    record.ipHash,
    record.userAgentHash,
    record.metadataJson,
    record.occurredAt,
    canonicalRecord,
    new TextEncoder().encode(canonicalRecord).byteLength,
  );
}

async function expectParentSealedAppendRejected(
  batchKey: string,
  ordinal: number,
  record: AuditArchiveRecordV1,
  expectedCount: number,
): Promise<void> {
  await expect(
    prepareSingleItemInsert(batchKey, ordinal, record).run(),
  ).rejects.toThrow(/audit archive item must precede parent/);
  expect(
    await env.PG72_ID_DB.prepare(
      `SELECT count(*) AS count FROM audit_archive_batch_item
        WHERE batch_key = ?`,
    )
      .bind(batchKey)
      .first<number>("count"),
  ).toBe(expectedCount);
  expect(
    await env.PG72_ID_DB.prepare(
      `SELECT count(*) AS count FROM audit_archive_batch_item
        WHERE event_id = ?`,
    )
      .bind(record.eventId)
      .first<number>("count"),
  ).toBe(0);
}

const parentInsertSql = `INSERT INTO audit_archive_batch
  (batch_key, batch_generation, checkpoint_revision,
   checkpoint_from_sequence, schema_version, contract, manifest_json,
   first_sequence, last_sequence, event_count, plaintext_bytes,
   plaintext_sha256, key_version, content_type, object_key, object_bytes,
   object_sha256, encrypted_envelope, status, dispatch_generation, attempts,
   next_attempt_at, lease_id, lease_expires_at, r2_version, r2_etag,
   r2_readback_sha256, r2_readback_at, archived_at, envelope_gc_at,
   last_error_code, manual_replay_audit_id, created_at, updated_at)
 VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
         'pending', 1, 0, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         NULL, NULL, ?, ?)`;

async function buildBatch(createdAt = at(10_000)): Promise<BatchBuild> {
  const checkpoint = await env.PG72_ID_DB.prepare(
    "SELECT revision, last_sequence FROM audit_archive_checkpoint WHERE id = 1",
  ).first<{ last_sequence: number; revision: number }>();
  if (!checkpoint) throw new Error("missing archive checkpoint");
  const records = await outstandingRecords();
  if (records.length === 0) throw new Error("no audit records to archive");
  const batchKey = reference();
  const sealed = await sealAuditArchiveV1({
    batchGeneration: checkpoint.revision + 1,
    checkpointFromSequence: checkpoint.last_sequence,
    createdAt,
    kek: ZERO_KEK,
    keyVersion: KEK_VERSION,
    records,
  });
  const plaintext = encodeCanonicalAuditRecordsV1(records);
  const recordArrayJson = JSON.stringify(records);
  return {
    batchKey,
    envelope: sealed.objectBytes,
    itemInsert: env.PG72_ID_DB.prepare(itemInsertSql).bind(
      batchKey,
      recordArrayJson,
    ),
    manifest: sealed.manifest,
    parentInsert: env.PG72_ID_DB.prepare(parentInsertSql).bind(
      batchKey,
      sealed.manifest.batchGeneration,
      checkpoint.revision,
      checkpoint.last_sequence,
      AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
      JSON.stringify(sealed.manifest),
      sealed.manifest.firstSequence,
      sealed.manifest.lastSequence,
      sealed.manifest.eventCount,
      plaintext.byteLength,
      sealed.manifest.plaintextSha256,
      sealed.manifest.keyVersion,
      AUDIT_ARCHIVE_CONTENT_TYPE,
      sealed.manifest.objectKey,
      sealed.manifest.objectBytes,
      sealed.manifest.objectSha256,
      sealed.objectBytes,
      createdAt,
      createdAt,
      createdAt,
    ),
    records,
  };
}

async function persistBatch(build: BatchBuild): Promise<void> {
  const results = await env.PG72_ID_DB.batch([
    build.itemInsert,
    build.parentInsert,
  ]);
  expect(results.map(({ meta }) => meta.changes)).toEqual([
    build.records.length,
    1,
  ]);
}

async function claimBatch(
  batchKey: string,
  attempt: number,
  updatedAt: string,
  expiresAt: string,
): Promise<string> {
  const leaseId = reference();
  const result = await env.PG72_ID_DB.prepare(
    `UPDATE audit_archive_batch
        SET status = 'processing', attempts = ?, next_attempt_at = NULL,
            lease_id = ?, lease_expires_at = ?, last_error_code = NULL,
            updated_at = ?
      WHERE batch_key = ?`,
  )
    .bind(attempt, leaseId, expiresAt, updatedAt, batchKey)
    .run();
  expect(result.meta.changes).toBe(2);
  expect(
    await env.PG72_ID_DB.prepare(
      `SELECT outcome FROM audit_archive_attempt WHERE id = ?`,
    )
      .bind(leaseId)
      .first<string>("outcome"),
  ).toBe("in_flight");
  return leaseId;
}

async function expectClaimRejected(
  batchKey: string,
  attempt: number,
  updatedAt: string,
  expiresAt: string,
): Promise<void> {
  const leaseId = reference();
  await expect(
    env.PG72_ID_DB.prepare(
      `UPDATE audit_archive_batch
          SET status = 'processing', attempts = ?, next_attempt_at = NULL,
              lease_id = ?, lease_expires_at = ?, last_error_code = NULL,
              updated_at = ?
        WHERE batch_key = ?`,
    )
      .bind(attempt, leaseId, expiresAt, updatedAt, batchKey)
      .run(),
  ).rejects.toThrow(/invalid audit archive batch transition/);
  expect(
    await env.PG72_ID_DB.prepare(
      "SELECT count(*) AS count FROM audit_archive_attempt WHERE id = ?",
    )
      .bind(leaseId)
      .first<number>("count"),
  ).toBe(0);
}

async function assertIntegrity(): Promise<void> {
  expect(
    (await env.PG72_ID_DB.prepare("PRAGMA foreign_key_check").all()).results,
  ).toEqual([]);
  expect(
    await env.PG72_ID_DB.prepare("PRAGMA quick_check").first<string>(
      "quick_check",
    ),
  ).toBe("ok");
}

describe("audit archive 0021 schema", () => {
  it("starts disabled with exactly six durable tables and captures audit source", async () => {
    const tables = await env.PG72_ID_DB.prepare(
      `SELECT name FROM sqlite_schema
        WHERE type = 'table' AND name GLOB 'audit_archive_*'
        ORDER BY name`,
    ).all<{ name: string }>();
    expect(tables.results.map(({ name }) => name)).toEqual([
      "audit_archive_attempt",
      "audit_archive_batch",
      "audit_archive_batch_item",
      "audit_archive_checkpoint",
      "audit_archive_key_sentinel",
      "audit_archive_source",
    ]);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT * FROM audit_archive_checkpoint WHERE id = 1",
      ).first(),
    ).toEqual({
      id: 1,
      last_archived_at: null,
      last_batch_key: null,
      last_sequence: 0,
      revision: 0,
    });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_key_sentinel",
      ).first<number>("count"),
    ).toBe(0);
    expect("AUDIT_ARCHIVE" in env).toBe(false);
    expect("AUDIT_ARCHIVE_DELIVERIES" in env).toBe(false);

    const event = await insertAuditEvent(1);
    expect(event.sequence).toBeGreaterThan(0);
    await env.PG72_ID_DB.prepare("DELETE FROM audit_event WHERE id = ?")
      .bind(event.eventId)
      .run();
    await assertIntegrity();
  });

  it("rejects non-canonical and impossible millisecond timestamps", async () => {
    const invalidTimestamps = [
      "2026-13-01T00:00:00.000Z",
      "2025-02-29T00:00:00.000Z",
      "2026-01-01T23:59:60.000Z",
      "2026-01-01T24:00:00.000Z",
    ];
    for (const [index, invalidTimestamp] of invalidTimestamps.entries()) {
      const keyVersion = `v${index + 1}`;
      await expect(
        env.PG72_ID_DB.prepare(
          `INSERT INTO audit_archive_key_sentinel
            (key_version, domain, fingerprint_ref, fingerprint_hash_version,
             created_at)
           VALUES (?, 'pgid.audit_archive_kek_fingerprint.v1', ?, 1, ?)`,
        )
          .bind(keyVersion, reference(100 + index), invalidTimestamp)
          .run(),
      ).rejects.toThrow(/CHECK constraint failed: length\("created_at"\) = 24/);
      expect(
        await env.PG72_ID_DB.prepare(
          `SELECT count(*) AS count FROM audit_archive_key_sentinel
            WHERE key_version = ?`,
        )
          .bind(keyVersion)
          .first<number>("count"),
      ).toBe(0);
    }
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_key_sentinel",
      ).first<number>("count"),
    ).toBe(0);
    await assertIntegrity();
  });

  it("rejects replacement and mutation while preserving audit compensation cascade", async () => {
    await env.PG72_ID_DB.prepare("PRAGMA recursive_triggers = OFF").run();
    const event = await insertAuditEvent(1, {
      eventId: `compensation:${crypto.randomUUID()}`,
    });
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE audit_archive_source SET event_id = event_id WHERE sequence = ?",
      )
        .bind(event.sequence)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "DELETE FROM audit_archive_source WHERE sequence = ?",
      )
        .bind(event.sequence)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "INSERT OR REPLACE INTO audit_archive_source (event_id) VALUES (?)",
      )
        .bind(event.eventId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO audit_event
          (id, event_type, outcome, occurred_at)
         VALUES (?, 'test.archive', 'success', ?)`,
      )
        .bind(event.eventId, at(2_000))
        .run(),
    ).rejects.toThrow();

    await env.PG72_ID_DB.prepare("DELETE FROM audit_event WHERE id = ?")
      .bind(event.eventId)
      .run();
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_source WHERE sequence = ?",
      )
        .bind(event.sequence)
        .first<number>("count"),
    ).toBe(0);

    await installSentinel(at(3_000));
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO audit_archive_key_sentinel
          (key_version, domain, fingerprint_ref, fingerprint_hash_version, created_at)
         VALUES ('v1', 'pgid.audit_archive_kek_fingerprint.v1', ?, 1, ?)`,
      )
        .bind(reference(92), at(4_000))
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "DELETE FROM audit_archive_key_sentinel WHERE key_version = 'v1'",
      ).run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE audit_archive_key_sentinel SET created_at = created_at
          WHERE key_version = 'v1'`,
      ).run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO audit_archive_checkpoint
          (id, revision, last_sequence, last_batch_key, last_archived_at)
         VALUES (1, 0, 0, NULL, NULL)`,
      ).run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "DELETE FROM audit_archive_checkpoint WHERE id = 1",
      ).run(),
    ).rejects.toThrow();
    await assertIntegrity();
  });

  it("persists one complete item-first prefix and accepts legitimate sequence gaps", async () => {
    await installSentinel(at(500));
    const first = await insertAuditEvent(1);
    const removed = await insertAuditEvent(2);
    const third = await insertAuditEvent(3);
    await env.PG72_ID_DB.prepare("DELETE FROM audit_event WHERE id = ?")
      .bind(removed.eventId)
      .run();
    expect(third.sequence - first.sequence).toBe(2);

    const build = await buildBatch(at(4_000));
    expect(build.records.map(({ sequence }) => sequence)).toEqual([
      first.sequence,
      third.sequence,
    ]);
    const truncated = build.records.slice(0, -1);
    await expect(
      env.PG72_ID_DB.batch([
        env.PG72_ID_DB.prepare(itemInsertSql).bind(
          build.batchKey,
          JSON.stringify(truncated),
        ),
        build.parentInsert,
      ]),
    ).rejects.toThrow();
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_batch_item",
      ).first<number>("count"),
    ).toBe(0);

    await persistBatch(build);
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT count(*) AS count FROM audit_archive_batch_item
          WHERE batch_key = ?`,
      )
        .bind(build.batchKey)
        .first<number>("count"),
    ).toBe(2);
    const pendingAppend = await insertAuditEvent(4, {
      occurredAt: at(5_000),
    });
    const pendingAppendRecord = (await outstandingRecords()).find(
      ({ eventId }) => eventId === pendingAppend.eventId,
    );
    if (!pendingAppendRecord) throw new Error("missing pending append record");
    await expectParentSealedAppendRejected(
      build.batchKey,
      3,
      pendingAppendRecord,
      2,
    );
    await env.PG72_ID_DB.prepare("DELETE FROM audit_event WHERE id = ?")
      .bind(pendingAppend.eventId)
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE audit_archive_batch_item SET ordinal = ordinal
          WHERE batch_key = ? AND ordinal = 1`,
      )
        .bind(build.batchKey)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO audit_archive_batch_item
         SELECT * FROM audit_archive_batch_item
          WHERE batch_key = ? AND ordinal = 1`,
      )
        .bind(build.batchKey)
        .run(),
    ).rejects.toThrow();
    const invalidLease = reference();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE audit_archive_batch
            SET status = 'processing', attempts = 1, next_attempt_at = NULL,
                lease_id = ?, lease_expires_at = '2026-07-18T24:00:00.000Z',
                updated_at = '2026-07-18T23:59:59.900Z'
          WHERE batch_key = ?`,
      )
        .bind(invalidLease, build.batchKey)
        .run(),
    ).rejects.toThrow();
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, attempts FROM audit_archive_batch
          WHERE batch_key = ?`,
      )
        .bind(build.batchKey)
        .first(),
    ).toEqual({ attempts: 0, status: "pending" });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_attempt WHERE id = ?",
      )
        .bind(invalidLease)
        .first<number>("count"),
    ).toBe(0);
    const lease = await claimBatch(
      build.batchKey,
      1,
      at(10_000),
      at(310_000),
    );
    const completedAt = at(309_600);
    await env.PG72_ID_DB.prepare(
      `UPDATE audit_archive_attempt
          SET outcome = 'archived', resulting_status = 'archived',
              r2_version = 'version-gap', r2_etag = 'etag-gap',
              r2_readback_sha256 = ?, r2_readback_at = ?, completed_at = ?
        WHERE id = ?`,
    )
      .bind(
        build.manifest.objectSha256,
        completedAt,
        completedAt,
        lease,
      )
      .run();
    const archivedAppend = await insertAuditEvent(5, {
      occurredAt: at(310_000),
    });
    const archivedAppendRecord = (await outstandingRecords()).find(
      ({ eventId }) => eventId === archivedAppend.eventId,
    );
    if (!archivedAppendRecord) throw new Error("missing archived append record");
    await expectParentSealedAppendRejected(
      build.batchKey,
      3,
      archivedAppendRecord,
      2,
    );
    await env.PG72_ID_DB.prepare("DELETE FROM audit_event WHERE id = ?")
      .bind(archivedAppend.eventId)
      .run();
    await assertIntegrity();
  });

  it("archives atomically and advances the checkpoint with recursive triggers off", async () => {
    await env.PG72_ID_DB.prepare("PRAGMA recursive_triggers = OFF").run();
    await installSentinel(at(500));
    await insertAuditEvent(400);
    const build = await buildBatch(at(401_000));
    await persistBatch(build);
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO audit_archive_batch
         SELECT * FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(build.batchKey)
        .run(),
    ).rejects.toThrow();
    const lease = await claimBatch(
      build.batchKey,
      1,
      at(401_100),
      at(701_100),
    );
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, r2_version,
                encrypted_envelope IS NOT NULL AS has_envelope
           FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(build.batchKey)
        .first(),
    ).toEqual({ has_envelope: 1, r2_version: null, status: "processing" });
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO audit_archive_attempt
         SELECT * FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(lease)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "DELETE FROM audit_archive_attempt WHERE id = ?",
      )
        .bind(lease)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE audit_archive_attempt
            SET outcome = 'archived', resulting_status = 'archived',
                r2_version = 'version-expired', r2_etag = 'etag-expired',
                r2_readback_sha256 = ?, r2_readback_at = ?, completed_at = ?
          WHERE id = ?`,
      )
        .bind(
          build.manifest.objectSha256,
          at(701_100),
          at(701_100),
          lease,
        )
        .run(),
    ).rejects.toThrow();
    const completedAt = at(700_700);
    await env.PG72_ID_DB.prepare(
      `UPDATE audit_archive_attempt
          SET outcome = 'archived', resulting_status = 'archived',
              r2_version = 'version-1', r2_etag = 'etag-1',
              r2_readback_sha256 = ?, r2_readback_at = ?, completed_at = ?
        WHERE id = ?`,
    )
      .bind(
        build.manifest.objectSha256,
        completedAt,
        completedAt,
        lease,
      )
      .run();
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, r2_version, archived_at, envelope_gc_at,
                encrypted_envelope IS NULL AS envelope_cleared
           FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(build.batchKey)
        .first(),
    ).toEqual({
      archived_at: completedAt,
      envelope_cleared: 1,
      envelope_gc_at: completedAt,
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
      last_batch_key: build.batchKey,
      last_sequence: build.manifest.lastSequence,
      revision: build.manifest.batchGeneration,
    });
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE audit_archive_attempt SET outcome = outcome WHERE id = ?",
      )
        .bind(lease)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "DELETE FROM audit_archive_batch WHERE batch_key = ?",
      )
        .bind(build.batchKey)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO audit_event
          (id, event_type, outcome, occurred_at)
         VALUES (?, 'test.archive', 'success', ?)`,
      )
        .bind(build.records[0]?.eventId, at(400_000))
        .run(),
    ).rejects.toThrow();
    await assertIntegrity();
  });

  it("orders retry scheduling at exact terminal milliseconds", async () => {
    await installSentinel(at(500));
    await insertAuditEvent(600);
    const build = await buildBatch(at(710_000));
    await persistBatch(build);
    const lease = await claimBatch(
      build.batchKey,
      1,
      at(710_100),
      at(1_010_100),
    );
    const completedAt = at(710_500);
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE audit_archive_attempt
            SET outcome = 'retry', resulting_status = 'retry',
                next_attempt_at = ?, error_code = 'r2_transient',
                completed_at = ?
          WHERE id = ?`,
      )
        .bind(at(710_499), completedAt, lease)
        .run(),
    ).rejects.toThrow(/CHECK constraint failed: next_attempt_at/);
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT outcome, next_attempt_at, completed_at
           FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(lease)
        .first(),
    ).toEqual({ completed_at: null, next_attempt_at: null, outcome: "in_flight" });

    await env.PG72_ID_DB.prepare(
      `UPDATE audit_archive_attempt
          SET outcome = 'retry', resulting_status = 'retry',
              next_attempt_at = ?, error_code = 'r2_transient',
              completed_at = ?
        WHERE id = ?`,
    )
      .bind(completedAt, completedAt, lease)
      .run();
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, attempts, next_attempt_at, updated_at
           FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(build.batchKey)
        .first(),
    ).toEqual({
      attempts: 1,
      next_attempt_at: completedAt,
      status: "retry",
      updated_at: completedAt,
    });
    await expectClaimRejected(
      build.batchKey,
      2,
      completedAt,
      at(1_010_500),
    );
    const secondLease = await claimBatch(
      build.batchKey,
      2,
      at(710_501),
      at(1_010_501),
    );
    const archivedAt = at(799_000);
    await env.PG72_ID_DB.prepare(
      `UPDATE audit_archive_attempt
          SET outcome = 'archived', resulting_status = 'archived',
              r2_version = 'version-retry', r2_etag = 'etag-retry',
              r2_readback_sha256 = ?, r2_readback_at = ?, completed_at = ?
        WHERE id = ?`,
    )
      .bind(
        build.manifest.objectSha256,
        archivedAt,
        archivedAt,
        secondLease,
      )
      .run();
    await assertIntegrity();
  });

  it("rejects delimiter-bearing R2 evidence on corrupt attempts", async () => {
    await installSentinel(at(500));
    await insertAuditEvent(700);
    const build = await buildBatch(at(800_000));
    await persistBatch(build);
    const lease = await claimBatch(
      build.batchKey,
      1,
      at(800_100),
      at(1_100_100),
    );
    const completedAt = at(800_500);
    const invalidEvidence = [
      { constraint: "r2_version", etag: "etag", version: "version\u0000suffix" },
      { constraint: "r2_version", etag: "etag", version: "version\nsuffix" },
      { constraint: "r2_version", etag: "etag", version: "version\rsuffix" },
      { constraint: "r2_etag", etag: "etag\u0000suffix", version: "version" },
      { constraint: "r2_etag", etag: "etag\nsuffix", version: "version" },
      { constraint: "r2_etag", etag: "etag\rsuffix", version: "version" },
    ] as const;
    for (const { constraint, etag, version } of invalidEvidence) {
      await expect(
        env.PG72_ID_DB.prepare(
          `UPDATE audit_archive_attempt
              SET outcome = 'corrupt', resulting_status = 'corrupt',
                  r2_version = ?, r2_etag = ?, r2_readback_sha256 = ?,
                  r2_readback_at = ?, error_code = 'r2_readback_mismatch',
                  completed_at = ?
            WHERE id = ?`,
        )
          .bind(
            version,
            etag,
            build.manifest.objectSha256,
            completedAt,
            completedAt,
            lease,
          )
          .run(),
      ).rejects.toThrow(new RegExp(`CHECK constraint failed: ${constraint}`));
      expect(
        await env.PG72_ID_DB.prepare(
          `SELECT outcome, r2_version, r2_etag, completed_at
             FROM audit_archive_attempt WHERE id = ?`,
        )
          .bind(lease)
          .first(),
      ).toEqual({
        completed_at: null,
        outcome: "in_flight",
        r2_etag: null,
        r2_version: null,
      });
    }

    await env.PG72_ID_DB.prepare(
      `UPDATE audit_archive_attempt
          SET outcome = 'archived', resulting_status = 'archived',
              r2_version = 'version-valid', r2_etag = 'etag-valid',
              r2_readback_sha256 = ?, r2_readback_at = ?,
              error_code = NULL, completed_at = ?
        WHERE id = ?`,
    )
      .bind(
        build.manifest.objectSha256,
        completedAt,
        completedAt,
        lease,
      )
      .run();
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT outcome, r2_version, r2_etag FROM audit_archive_attempt
          WHERE id = ?`,
      )
        .bind(lease)
        .first(),
    ).toEqual({
      outcome: "archived",
      r2_etag: "etag-valid",
      r2_version: "version-valid",
    });
    await assertIntegrity();
  });

  it("uses exact millisecond lease boundaries through attempts one to five", async () => {
    await env.PG72_ID_DB.prepare("PRAGMA recursive_triggers = OFF").run();
    await installSentinel(at(500));
    await insertAuditEvent(800);
    const build = await buildBatch(at(801_000));
    await persistBatch(build);

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const attemptBase = 1_000_000 + attempt * 400_000;
      const claimAt = at(attemptBase + 500);
      const expiresAt = at(attemptBase + 300_500);
      const lease = await claimBatch(
        build.batchKey,
        attempt,
        claimAt,
        expiresAt,
      );
      const premature = at(attemptBase + 300_100);
      await expect(
        env.PG72_ID_DB.prepare(
          `UPDATE audit_archive_attempt
              SET outcome = 'lease_expired',
                  resulting_status = ?, next_attempt_at = ?,
                  error_code = 'lease_expired', completed_at = ?
            WHERE id = ?`,
        )
          .bind(
            attempt === 5 ? "dead" : "retry",
            attempt === 5 ? null : at(attemptBase + 301_500),
            premature,
            lease,
          )
          .run(),
      ).rejects.toThrow();
      expect(
        await env.PG72_ID_DB.prepare(
          "SELECT outcome FROM audit_archive_attempt WHERE id = ?",
        )
          .bind(lease)
          .first<string>("outcome"),
      ).toBe("in_flight");

      if (attempt < 5) {
        await expect(
          env.PG72_ID_DB.prepare(
            `UPDATE audit_archive_attempt
                SET outcome = 'lease_expired', resulting_status = 'retry',
                    next_attempt_at = ?, error_code = 'lease_expired',
                    completed_at = ?
              WHERE id = ?`,
          )
            .bind(at(attemptBase + 300_499), expiresAt, lease)
            .run(),
        ).rejects.toThrow(/CHECK constraint failed: next_attempt_at/);
        expect(
          await env.PG72_ID_DB.prepare(
            "SELECT outcome FROM audit_archive_attempt WHERE id = ?",
          )
            .bind(lease)
            .first<string>("outcome"),
        ).toBe("in_flight");
      }

      const nextAttemptAt = attempt === 5
        ? null
        : expiresAt;
      await env.PG72_ID_DB.prepare(
        `UPDATE audit_archive_attempt
            SET outcome = 'lease_expired',
                resulting_status = ?, next_attempt_at = ?,
                error_code = 'lease_expired', completed_at = ?
          WHERE id = ?`,
      )
        .bind(
          attempt === 5 ? "dead" : "retry",
          nextAttemptAt,
          expiresAt,
          lease,
        )
        .run();
      expect(
        await env.PG72_ID_DB.prepare(
          "SELECT status FROM audit_archive_batch WHERE batch_key = ?",
        )
          .bind(build.batchKey)
          .first<string>("status"),
      ).toBe(attempt === 5 ? "dead" : "retry");
      if (attempt < 5) {
        await expectClaimRejected(
          build.batchKey,
          attempt + 1,
          expiresAt,
          at(attemptBase + 600_500),
        );
      }
    }

    const envelopeBytes = await env.PG72_ID_DB.prepare(
      `SELECT length(encrypted_envelope) AS bytes FROM audit_archive_batch
        WHERE batch_key = ?`,
    )
      .bind(build.batchKey)
      .first<number>("bytes");
    const replayAt = at(3_500_000);
    const replayAudit = crypto.randomUUID();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE audit_archive_batch
            SET status = 'pending', dispatch_generation = 2, attempts = 0,
                next_attempt_at = ?, last_error_code = NULL,
                manual_replay_audit_id = ?, updated_at = ?
          WHERE batch_key = ?`,
      )
        .bind(replayAt, replayAudit, replayAt, build.batchKey)
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO audit_event
        (id, event_type, subject_id, outcome, metadata_json, occurred_at)
       VALUES (?, 'audit.archive.manual_replay', ?, 'success', ?, ?)`,
    )
      .bind(
        replayAudit,
        build.batchKey,
        JSON.stringify({ dispatchGeneration: 2 }),
        replayAt,
      )
      .run();
    await env.PG72_ID_DB.prepare(
      `UPDATE audit_archive_batch
          SET status = 'pending', dispatch_generation = 2, attempts = 0,
              next_attempt_at = ?, last_error_code = NULL,
              manual_replay_audit_id = ?, updated_at = ?
        WHERE batch_key = ?`,
    )
      .bind(replayAt, replayAudit, replayAt, build.batchKey)
      .run();
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, dispatch_generation, attempts,
                length(encrypted_envelope) AS envelope_bytes
           FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(build.batchKey)
        .first(),
    ).toEqual({
      attempts: 0,
      dispatch_generation: 2,
      envelope_bytes: envelopeBytes,
      status: "pending",
    });
    const replayLease = await claimBatch(
      build.batchKey,
      1,
      at(3_501_000),
      at(3_801_000),
    );
    const archivedAt = at(3_800_600);
    await env.PG72_ID_DB.prepare(
      `UPDATE audit_archive_attempt
          SET outcome = 'archived', resulting_status = 'archived',
              r2_version = 'version-replay', r2_etag = 'etag-replay',
              r2_readback_sha256 = ?, r2_readback_at = ?, completed_at = ?
        WHERE id = ?`,
    )
      .bind(
        build.manifest.objectSha256,
        archivedAt,
        archivedAt,
        replayLease,
      )
      .run();
    await assertIntegrity();
  });

  it("rolls terminal attempt, R2 evidence, BLOB GC and batch state back on a stale checkpoint", async () => {
    await env.PG72_ID_DB.prepare("PRAGMA recursive_triggers = OFF").run();
    await installSentinel(at(500));
    await insertAuditEvent(4_000);
    const build = await buildBatch(at(4_001_000));
    await persistBatch(build);
    const lease = await claimBatch(
      build.batchKey,
      1,
      at(4_002_000),
      at(4_302_000),
    );

    const checkpointGuard = await env.PG72_ID_DB.prepare(
      `SELECT sql FROM sqlite_schema
        WHERE type = 'trigger'
          AND name = 'audit_archive_checkpoint_transition_guard'`,
    ).first<string>("sql");
    if (!checkpointGuard) throw new Error("missing checkpoint guard SQL");
    await env.PG72_ID_DB.prepare(
      "DROP TRIGGER audit_archive_checkpoint_transition_guard",
    ).run();
    await env.PG72_ID_DB.prepare(
      `UPDATE audit_archive_checkpoint
          SET revision = 1, last_sequence = 900,
              last_batch_key = ?, last_archived_at = ?
        WHERE id = 1`,
    )
      .bind(reference(), at(4_003_000))
      .run();
    await env.PG72_ID_DB.prepare(checkpointGuard).run();

    const completedAt = at(4_301_600);
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE audit_archive_attempt
            SET outcome = 'archived', resulting_status = 'archived',
                r2_version = 'version-stale', r2_etag = 'etag-stale',
                r2_readback_sha256 = ?, r2_readback_at = ?, completed_at = ?
          WHERE id = ?`,
      )
        .bind(
          build.manifest.objectSha256,
          completedAt,
          completedAt,
          lease,
        )
        .run(),
    ).rejects.toThrow();
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT outcome, completed_at FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(lease)
        .first(),
    ).toEqual({ completed_at: null, outcome: "in_flight" });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, r2_version, encrypted_envelope IS NOT NULL AS has_envelope
           FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(build.batchKey)
        .first(),
    ).toEqual({ has_envelope: 1, r2_version: null, status: "processing" });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT revision, last_sequence FROM audit_archive_checkpoint WHERE id = 1",
      ).first(),
    ).toEqual({ last_sequence: 900, revision: 1 });
    await assertIntegrity();
  });
});
