import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync, backup } from "node:sqlite";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  applyAllMigrations,
  executeD1,
} from "./d1-manifest.mjs";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const migrationsDirectory = path.join(repositoryRoot, "apps", "sso", "migrations");
const migrationNames = readdirSync(migrationsDirectory)
  .filter((name) => name.endsWith(".sql"))
  .sort();

function migration(name) {
  return readFileSync(path.join(migrationsDirectory, name), "utf8");
}

function openDatabase(filename = ":memory:") {
  const database = new DatabaseSync(filename);
  database.exec("PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = OFF;");
  return database;
}

function applyThrough(database, head) {
  for (const name of migrationNames) {
    database.exec(migration(name));
    if (name === head) return;
  }
  throw new Error(`migration head not found: ${head}`);
}

function integrity(database) {
  assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
  assert.deepEqual({ ...database.prepare("PRAGMA quick_check").get() }, {
    quick_check: "ok",
  });
}

function archiveTableNames(database) {
  return database
    .prepare(
      `SELECT name FROM sqlite_schema
        WHERE type = 'table' AND name GLOB 'audit_archive_*'
        ORDER BY name`,
    )
    .all()
    .map(({ name }) => name);
}

const expectedArchiveTables = [
  "audit_archive_attempt",
  "audit_archive_batch",
  "audit_archive_batch_item",
  "audit_archive_checkpoint",
  "audit_archive_key_sentinel",
  "audit_archive_source",
];

const expectedArchiveTriggers = [
  "audit_archive_attempt_apply_terminal",
  "audit_archive_attempt_current_r2_evidence_guard",
  "audit_archive_attempt_delete_guard",
  "audit_archive_attempt_insert_guard",
  "audit_archive_attempt_transition_guard",
  "audit_archive_batch_advance_checkpoint",
  "audit_archive_batch_claim_attempt",
  "audit_archive_batch_delete_guard",
  "audit_archive_batch_identity_update_guard",
  "audit_archive_batch_insert_guard",
  "audit_archive_batch_item_delete_guard",
  "audit_archive_batch_item_insert_guard",
  "audit_archive_batch_item_update_guard",
  "audit_archive_batch_transition_guard",
  "audit_archive_checkpoint_delete_guard",
  "audit_archive_checkpoint_insert_guard",
  "audit_archive_checkpoint_transition_guard",
  "audit_archive_key_sentinel_delete_guard",
  "audit_archive_key_sentinel_insert_guard",
  "audit_archive_key_sentinel_update_guard",
  "audit_archive_source_delete_guard",
  "audit_archive_source_insert_guard",
  "audit_archive_source_parent_time_guard",
  "audit_archive_source_update_guard",
  "audit_event_archive_identity_insert_guard",
  "audit_event_archive_source_insert",
];

const expectedArchiveIndexes = [
  "audit_archive_attempt_error_idx",
  "audit_archive_attempt_outcome_idx",
  "audit_archive_attempt_time_idx",
  "audit_archive_batch_due_idx",
  "audit_archive_batch_expired_lease_idx",
  "audit_archive_batch_operator_idx",
  "sqlite_autoindex_audit_archive_attempt_1",
  "sqlite_autoindex_audit_archive_attempt_2",
  "sqlite_autoindex_audit_archive_attempt_3",
  "sqlite_autoindex_audit_archive_batch_1",
  "sqlite_autoindex_audit_archive_batch_2",
  "sqlite_autoindex_audit_archive_batch_3",
  "sqlite_autoindex_audit_archive_batch_4",
  "sqlite_autoindex_audit_archive_batch_5",
  "sqlite_autoindex_audit_archive_batch_6",
  "sqlite_autoindex_audit_archive_batch_item_1",
  "sqlite_autoindex_audit_archive_batch_item_2",
  "sqlite_autoindex_audit_archive_batch_item_3",
  "sqlite_autoindex_audit_archive_checkpoint_1",
  "sqlite_autoindex_audit_archive_key_sentinel_1",
  "sqlite_autoindex_audit_archive_key_sentinel_2",
  "sqlite_autoindex_audit_archive_source_1",
];

const archiveTableOrder = {
  audit_archive_attempt: "id",
  audit_archive_batch: "batch_key",
  audit_archive_batch_item: "batch_key, ordinal",
  audit_archive_checkpoint: "id",
  audit_archive_key_sentinel: "key_version",
  audit_archive_source: "sequence",
};

const archiveTableColumns = {
  audit_archive_attempt: [
    "id", "batch_key", "dispatch_generation", "attempt_number", "lease_id",
    "outcome", "resulting_status", "next_attempt_at", "r2_version", "r2_etag",
    "r2_observed_bytes", "r2_stored_sha256", "r2_readback_sha256",
    "r2_readback_at", "r2_conflict_evidence_format", "error_code",
    "started_at", "completed_at",
  ],
  audit_archive_batch: [
    "batch_key", "batch_generation", "checkpoint_revision",
    "checkpoint_from_sequence", "schema_version", "contract", "manifest_json",
    "first_sequence", "last_sequence", "event_count", "plaintext_bytes",
    "plaintext_sha256", "key_version", "content_type", "object_key",
    "object_bytes", "object_sha256", "encrypted_envelope", "status",
    "dispatch_generation", "attempts", "next_attempt_at", "lease_id",
    "lease_expires_at", "r2_version", "r2_etag", "r2_readback_sha256",
    "r2_readback_at", "archived_at", "envelope_gc_at", "last_error_code",
    "manual_replay_audit_id", "created_at", "updated_at",
  ],
  audit_archive_batch_item: [
    "batch_key", "ordinal", "source_sequence", "event_id", "event_type",
    "actor_user_id", "actor_ref", "actor_ref_hash_version", "subject_id",
    "client_id", "session_id", "outcome", "ip_hash", "user_agent_hash",
    "metadata_json", "occurred_at", "canonical_record_json",
    "canonical_record_bytes",
  ],
  audit_archive_checkpoint: [
    "id", "revision", "last_sequence", "last_batch_key", "last_archived_at",
  ],
  audit_archive_key_sentinel: [
    "key_version", "domain", "fingerprint_ref", "fingerprint_hash_version",
    "created_at",
  ],
  audit_archive_source: ["sequence", "event_id"],
};

const runnerResultTags = [
  "ledger",
  "schema",
  ...expectedArchiveTables.map((table) => `archive:${table}`),
  ...expectedArchiveTables.map((table) => `columns:${table}`),
  "quick_check",
  "foreign_keys",
  "temporary_tables",
];

const runnerSqlResultTags = runnerResultTags.filter(
  (tag) => tag !== "quick_check" && tag !== "foreign_keys",
);

function quotedIdentifier(value) {
  assert.match(value, /^[a-z0-9_]+$/);
  return `"${value}"`;
}

function taggedJsonRowsSql(tag, rowSql) {
  assert.match(tag, /^[a-z0-9_:]+$/);
  return `SELECT '${tag}' AS tag,
      COALESCE(json_group_array(json(row_json)), '[]') AS payload
    FROM (${rowSql})`;
}

function runnerArchiveRowsSql(table) {
  const columns = archiveTableColumns[table];
  assert.ok(columns);
  const values = columns.map((column) =>
    column === "encrypted_envelope"
      ? `CASE WHEN "encrypted_envelope" IS NULL THEN NULL
          ELSE hex("encrypted_envelope") END`
      : quotedIdentifier(column)
  );
  return taggedJsonRowsSql(
    `archive:${table}`,
    `SELECT json_array(${values.join(", ")}) AS row_json
       FROM ${quotedIdentifier(table)}
      ORDER BY ${archiveTableOrder[table]}`,
  );
}

function runnerArchiveColumnsSql(table) {
  assert.ok(archiveTableColumns[table]);
  return taggedJsonRowsSql(
    `columns:${table}`,
    `SELECT json_array(cid, name, type, "notnull", dflt_value, pk) AS row_json
       FROM pragma_table_info('${table}') ORDER BY cid`,
  );
}

function decodeTaggedRunnerResults(results) {
  assert.ok(Array.isArray(results));
  const expected = new Set(runnerResultTags);
  const tagged = new Map();
  for (const result of results) {
    assert.ok(result && typeof result === "object");
    assert.ok(Array.isArray(result.results));
    assert.equal(result.results.length, 1, "runner result must retain one tag row");
    const row = result.results[0];
    assert.deepEqual(Object.keys(row).sort(), ["payload", "tag"]);
    assert.equal(typeof row.tag, "string");
    assert.equal(typeof row.payload, "string");
    assert.ok(expected.has(row.tag), "runner result returned an unknown tag");
    assert.equal(tagged.has(row.tag), false, "runner result repeated a tag");
    const payload = JSON.parse(row.payload);
    assert.ok(Array.isArray(payload), "runner tag payload must be an array");
    tagged.set(row.tag, payload);
  }
  assert.equal(tagged.size, runnerResultTags.length, "runner result omitted a tag");
  return tagged;
}

function taggedTupleRows(tagged, tag, arity) {
  const rows = tagged.get(tag);
  assert.ok(Array.isArray(rows), `runner result omitted ${tag}`);
  for (const row of rows) {
    assert.ok(Array.isArray(row), `${tag} row must be an array`);
    assert.equal(row.length, arity, `${tag} row has the wrong arity`);
    for (const value of row) {
      assert.ok(
        value === null || typeof value === "number" || typeof value === "string",
        `${tag} row contains an invalid value type`,
      );
      if (typeof value === "number") assert.ok(Number.isFinite(value));
    }
  }
  return rows;
}

function archiveRows(database) {
  return Object.fromEntries(
    expectedArchiveTables.map((table) => [
      table,
      database.prepare(
        `SELECT * FROM "${table}" ORDER BY ${archiveTableOrder[table]}`,
      ).all().map((row) => ({ ...row })),
    ]),
  );
}

function assertFinalArchiveSchema(database) {
  assert.deepEqual(archiveTableNames(database), expectedArchiveTables);
  for (const table of expectedArchiveTables) {
    assert.deepEqual(
      database.prepare(`PRAGMA table_info(${quotedIdentifier(table)})`).all()
        .map(({ name }) => name),
      archiveTableColumns[table],
    );
  }
  assert.deepEqual(
    database.prepare(
      `SELECT name FROM sqlite_schema
        WHERE type = 'trigger'
          AND (name GLOB 'audit_archive_*' OR name GLOB 'audit_event_archive_*')
        ORDER BY name`,
    ).all().map(({ name }) => name),
    expectedArchiveTriggers,
  );
  const indexes = database.prepare(
    `SELECT name, sql IS NULL AS implicit FROM sqlite_schema
      WHERE type = 'index' AND tbl_name GLOB 'audit_archive_*'
      ORDER BY name`,
  ).all().map((row) => ({ ...row }));
  assert.deepEqual(indexes.map(({ name }) => name), expectedArchiveIndexes);
  assert.equal(indexes.filter(({ implicit }) => implicit === 0).length, 6);
  assert.equal(indexes.filter(({ implicit }) => implicit === 1).length, 16);
  assert.equal(
    database.prepare(
      `SELECT count(*) AS count FROM sqlite_temp_schema
        WHERE type = 'table' AND name GLOB 'audit_archive_*'`,
    ).get().count,
    0,
  );
  evidenceGuardSql(database);
}

function sha256File(filename) {
  return createHash("sha256").update(readFileSync(filename)).digest("hex");
}

function createMigrationRunnerProject(projectDirectory, names) {
  const fixtureMigrations = path.join(projectDirectory, "migrations");
  mkdirSync(fixtureMigrations, { mode: 0o700, recursive: true });
  for (const name of names) {
    copyFileSync(
      path.join(migrationsDirectory, name),
      path.join(fixtureMigrations, name),
    );
  }
  writeFileSync(
    path.join(projectDirectory, "wrangler.jsonc"),
    `${JSON.stringify({
      compatibility_date: "2026-07-18",
      d1_databases: [
        {
          binding: "PG72_ID_DB",
          database_id: "00000000-0000-0000-0000-000000000024",
          database_name: "pgid-audit-migration-idempotency-local",
          migrations_dir: fixtureMigrations,
        },
      ],
      main: path.join(repositoryRoot, "apps", "sso", "worker", "index.ts"),
      name: "pgid-audit-migration-idempotency-local",
    }, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
  return fixtureMigrations;
}

function runnerQueryRows(projectDirectory, sql) {
  const results = executeD1(projectDirectory, sql);
  assert.equal(results.length, 1);
  return (results[0].results ?? []).map((row) => ({ ...row }));
}

function incrementalRunnerSnapshot(projectDirectory) {
  return {
    consents: runnerQueryRows(
      projectDirectory,
      `SELECT id, clientId, userId, referenceId, scopes, createdAt, updatedAt
         FROM oauthConsent ORDER BY id`,
    ),
    foreignKeys: runnerQueryRows(projectDirectory, "PRAGMA foreign_key_check"),
    ledger: runnerQueryRows(
      projectDirectory,
      "SELECT id, name FROM d1_migrations ORDER BY id",
    ),
    quickCheck: runnerQueryRows(projectDirectory, "PRAGMA quick_check"),
  };
}

function runnerSnapshot(projectDirectory) {
  const statements = [
    taggedJsonRowsSql(
      "ledger",
      `SELECT json_array(id, name) AS row_json
         FROM d1_migrations ORDER BY id`,
    ),
    taggedJsonRowsSql(
      "schema",
      `SELECT json_array(type, name, tbl_name, sql) AS row_json
         FROM sqlite_schema
        WHERE name GLOB 'audit_archive_*'
           OR name GLOB 'audit_event_archive_*'
           OR tbl_name GLOB 'audit_archive_*'
        ORDER BY type, name, tbl_name`,
    ),
    ...expectedArchiveTables.map(runnerArchiveRowsSql),
    ...expectedArchiveTables.map(runnerArchiveColumnsSql),
    taggedJsonRowsSql(
      "temporary_tables",
      `SELECT json_array(count(*)) AS row_json
         FROM sqlite_temp_schema
        WHERE type = 'table' AND name GLOB 'audit_archive_*'`,
    ),
  ];
  assert.equal(statements.length, runnerSqlResultTags.length);
  const results = statements.map((statement, index) => {
    const output = executeD1(projectDirectory, statement);
    assert.equal(
      output.length,
      1,
      `runner query ${runnerSqlResultTags[index]} returned multiple result sets`,
    );
    return output[0];
  });
  const quickResults = executeD1(projectDirectory, "PRAGMA quick_check");
  assert.equal(quickResults.length, 1);
  const quickRows = quickResults[0].results ?? [];
  for (const row of quickRows) {
    assert.deepEqual(Object.keys(row), ["quick_check"]);
  }
  results.push(
    taggedRunnerFixture(
      "quick_check",
      quickRows.map(({ quick_check: value }) => [value]),
    ),
  );
  const foreignKeyResults = executeD1(
    projectDirectory,
    "PRAGMA foreign_key_check",
  );
  assert.equal(foreignKeyResults.length, 1);
  const foreignKeyRows = foreignKeyResults[0].results ?? [];
  for (const row of foreignKeyRows) {
    assert.deepEqual(Object.keys(row).sort(), ["fkid", "parent", "rowid", "table"]);
  }
  results.push(
    taggedRunnerFixture(
      "foreign_keys",
      foreignKeyRows.map((row) => [row.table, row.rowid, row.parent, row.fkid]),
    ),
  );
  const tagged = decodeTaggedRunnerResults(results);
  const ledgerRows = taggedTupleRows(tagged, "ledger", 2);
  for (const [id, name] of ledgerRows) {
    assert.ok(Number.isSafeInteger(id) && id > 0);
    assert.equal(typeof name, "string");
    assert.match(name, /^\d{4}_[a-z0-9_]+\.sql$/);
  }
  const ledger = ledgerRows.map(([id, name]) => ({ id, name }));
  const schemaRows = taggedTupleRows(tagged, "schema", 4);
  for (const [type, name, table, sql] of schemaRows) {
    assert.ok(["index", "table", "trigger"].includes(type));
    assert.equal(typeof name, "string");
    assert.equal(typeof table, "string");
    assert.ok(sql === null || typeof sql === "string");
  }
  const schema = schemaRows.map(([type, name, table, sql]) => ({
    name,
    sql,
    tbl_name: table,
    type,
  }));
  const rows = Object.fromEntries(
    expectedArchiveTables.map((table) => [
      table,
      taggedTupleRows(
        tagged,
        `archive:${table}`,
        archiveTableColumns[table].length,
      ),
    ]),
  );
  const columns = Object.fromEntries(
    expectedArchiveTables.map((table) => [
      table,
      taggedTupleRows(tagged, `columns:${table}`, 6),
    ]),
  );
  for (const table of expectedArchiveTables) {
    for (const [cid, name, type, notNull, defaultValue, primaryKey] of columns[table]) {
      assert.ok(Number.isSafeInteger(cid) && cid >= 0);
      assert.equal(typeof name, "string");
      assert.equal(typeof type, "string");
      assert.ok(notNull === 0 || notNull === 1);
      assert.ok(defaultValue === null || typeof defaultValue === "string");
      assert.ok(Number.isSafeInteger(primaryKey) && primaryKey >= 0);
    }
    assert.deepEqual(
      columns[table].map(([, name]) => name),
      archiveTableColumns[table],
    );
  }
  for (const row of rows.audit_archive_batch) {
    const encryptedEnvelope = row[archiveTableColumns.audit_archive_batch.indexOf(
      "encrypted_envelope",
    )];
    assert.ok(
      encryptedEnvelope === null ||
        (typeof encryptedEnvelope === "string" &&
          /^[A-F0-9]*$/.test(encryptedEnvelope)),
    );
  }
  const quickCheck = taggedTupleRows(tagged, "quick_check", 1);
  const foreignKeys = taggedTupleRows(tagged, "foreign_keys", 4);
  const temporaryTables = taggedTupleRows(tagged, "temporary_tables", 1);
  for (const [value] of quickCheck) assert.equal(typeof value, "string");
  for (const [table, rowId, parent, foreignKeyId] of foreignKeys) {
    assert.equal(typeof table, "string");
    assert.ok(rowId === null || Number.isSafeInteger(rowId));
    assert.equal(typeof parent, "string");
    assert.ok(Number.isSafeInteger(foreignKeyId));
  }
  for (const [count] of temporaryTables) {
    assert.ok(Number.isSafeInteger(count) && count >= 0);
  }
  return {
    archiveHistorySha256: createHash("sha256")
      .update(JSON.stringify(rows))
      .digest("hex"),
    columns,
    foreignKeys,
    ledger,
    quickCheck,
    rows,
    schema,
    temporaryTables,
  };
}

function assertRunnerFinalArchiveSchema(snapshot) {
  assert.deepEqual(
    snapshot.schema
      .filter(({ name, type }) => type === "table" && name.startsWith("audit_archive_"))
      .map(({ name }) => name),
    expectedArchiveTables,
  );
  assert.deepEqual(
    snapshot.schema
      .filter(({ name, type }) =>
        type === "trigger" &&
        (name.startsWith("audit_archive_") || name.startsWith("audit_event_archive_"))
      )
      .map(({ name }) => name),
    expectedArchiveTriggers,
  );
  const indexes = snapshot.schema.filter(
    ({ tbl_name: table, type }) =>
      type === "index" && table.startsWith("audit_archive_"),
  );
  assert.deepEqual(indexes.map(({ name }) => name), expectedArchiveIndexes);
  assert.equal(indexes.filter(({ sql }) => sql !== null).length, 6);
  assert.equal(indexes.filter(({ sql }) => sql === null).length, 16);
  assert.deepEqual(snapshot.temporaryTables, [[0]]);
}

function evidenceGuardSql(database) {
  const row = database.prepare(
    `SELECT sql FROM sqlite_schema
      WHERE type = 'trigger'
        AND name = 'audit_archive_attempt_current_r2_evidence_guard'`,
  ).get();
  assert.equal(typeof row?.sql, "string");
  assert.match(
    row.sql,
    /RAISE\(ABORT, 'current R2 evidence requires observed bytes'\)/,
  );
  return row.sql;
}

function seedClaimedArchiveBatch(database) {
  const occurredAt = "2026-07-18T04:00:00.000Z";
  const createdAt = "2026-07-18T04:00:01.000Z";
  const claimedAt = "2026-07-18T04:00:02.000Z";
  const leaseExpiresAt = "2026-07-18T04:03:02.000Z";
  const completedAt = "2026-07-18T04:02:00.000Z";
  const eventId = "restore:event";
  database.prepare(
    `INSERT INTO audit_event
      (id, event_type, subject_id, outcome, metadata_json, occurred_at)
     VALUES (?, 'test.archive', 'restore:subject', 'success',
             '{"kind":"restore_test"}', ?)`,
  ).run(eventId, occurredAt);
  const { sequence } = database.prepare(
    "SELECT sequence FROM audit_archive_source WHERE event_id = ?",
  ).get(eventId);
  database.prepare(
    `INSERT INTO audit_archive_key_sentinel
      (key_version, domain, fingerprint_ref, fingerprint_hash_version, created_at)
     VALUES ('v1', 'pgid.audit_archive_kek_fingerprint.v1', ?, 1, ?)`,
  ).run("A".repeat(43), createdAt);

  const batchKey = `${"B".repeat(42)}E`;
  const leaseId = `${"C".repeat(42)}E`;
  const objectSha256 = "1".repeat(64);
  const plaintextSha256 = "2".repeat(64);
  const objectBytes = new Uint8Array([1, 2, 3]);
  const objectKey = `audit/v1/${String(sequence).padStart(16, "0")}-${String(
    sequence,
  ).padStart(16, "0")}/${objectSha256}.pgid-audit`;
  const metadataJson = '{"kind":"restore_test"}';
  const record = {
    actorRef: null,
    actorRefHashVersion: null,
    actorUserId: null,
    clientId: null,
    eventId,
    eventType: "test.archive",
    ipHash: null,
    metadataJson,
    occurredAt,
    outcome: "success",
    sequence,
    sessionId: null,
    subjectId: "restore:subject",
    userAgentHash: null,
  };
  const canonicalRecord = JSON.stringify(record);
  const plaintextBytes = Buffer.byteLength(
    JSON.stringify({
      contract: "pgid-audit-records-v1",
      records: [record],
      schemaVersion: 1,
    }),
  );
  const manifest = {
    batchGeneration: 1,
    checkpointFromSequence: 0,
    contentType: "application/vnd.pg72.pgid-audit-archive+json",
    contract: "pgid-audit-archive-v1",
    createdAt,
    eventCount: 1,
    firstSequence: sequence,
    keyVersion: "v1",
    lastSequence: sequence,
    objectBytes: objectBytes.byteLength,
    objectKey,
    objectSha256,
    plaintextSha256,
    schemaVersion: 1,
  };

  database.exec("BEGIN");
  try {
    database.prepare(
      `INSERT INTO audit_archive_batch_item
        (batch_key, ordinal, source_sequence, event_id, event_type,
         actor_user_id, actor_ref, actor_ref_hash_version, subject_id,
         client_id, session_id, outcome, ip_hash, user_agent_hash,
         metadata_json, occurred_at, canonical_record_json,
         canonical_record_bytes)
       VALUES (?, 1, ?, ?, 'test.archive', NULL, NULL, NULL, 'restore:subject',
               NULL, NULL, 'success', NULL, NULL, ?, ?, ?, ?)`,
    ).run(
      batchKey,
      sequence,
      eventId,
      metadataJson,
      occurredAt,
      canonicalRecord,
      Buffer.byteLength(canonicalRecord),
    );
    database.prepare(
      `INSERT INTO audit_archive_batch
        (batch_key, batch_generation, checkpoint_revision,
         checkpoint_from_sequence, schema_version, contract, manifest_json,
         first_sequence, last_sequence, event_count, plaintext_bytes,
         plaintext_sha256, key_version, content_type, object_key,
         object_bytes, object_sha256, encrypted_envelope, status,
         dispatch_generation, attempts, next_attempt_at, lease_id,
         lease_expires_at, r2_version, r2_etag, r2_readback_sha256,
         r2_readback_at, archived_at, envelope_gc_at, last_error_code,
         manual_replay_audit_id, created_at, updated_at)
       VALUES (?, 1, 0, 0, 1, 'pgid-audit-archive-v1', ?, ?, ?, 1, ?, ?,
               'v1', 'application/vnd.pg72.pgid-audit-archive+json', ?, ?, ?,
               ?, 'pending', 1, 0, ?, NULL, NULL, NULL, NULL, NULL, NULL,
               NULL, NULL, NULL, NULL, ?, ?)`,
    ).run(
      batchKey,
      JSON.stringify(manifest),
      sequence,
      sequence,
      plaintextBytes,
      plaintextSha256,
      objectKey,
      objectBytes.byteLength,
      objectSha256,
      objectBytes,
      createdAt,
      createdAt,
      createdAt,
    );
    database.exec("COMMIT");
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }

  database.prepare(
    `UPDATE audit_archive_batch
        SET status = 'processing', attempts = 1, next_attempt_at = NULL,
            lease_id = ?, lease_expires_at = ?, updated_at = ?
      WHERE batch_key = ?`,
  ).run(leaseId, leaseExpiresAt, claimedAt, batchKey);
  return {
    batchKey,
    completedAt,
    leaseId,
    objectBytes: objectBytes.byteLength,
    objectSha256,
  };
}

function taggedRunnerFixture(tag, payload = []) {
  return { results: [{ payload: JSON.stringify(payload), tag }] };
}

test("runner result decoder authenticates shuffled tagged result sets", () => {
  const shuffled = runnerResultTags
    .map((tag) => taggedRunnerFixture(tag, [[tag]]))
    .toReversed();
  const decoded = decodeTaggedRunnerResults(shuffled);
  assert.deepEqual([...decoded.keys()].sort(), [...runnerResultTags].sort());
  for (const tag of runnerResultTags) {
    assert.deepEqual(decoded.get(tag), [[tag]]);
  }
});

test("runner result decoder rejects missing, duplicate, unknown, and malformed tags", () => {
  const valid = runnerResultTags.map((tag) => taggedRunnerFixture(tag));
  const mutations = [
    valid.slice(1),
    [...valid, taggedRunnerFixture(runnerResultTags[0])],
    [...valid.slice(0, -1), taggedRunnerFixture("unknown")],
    [{ results: [] }, ...valid.slice(1)],
    [
      { results: [{ extra: true, payload: "[]", tag: runnerResultTags[0] }] },
      ...valid.slice(1),
    ],
    [
      { results: [{ payload: "{}", tag: runnerResultTags[0] }] },
      ...valid.slice(1),
    ],
  ];
  for (const mutation of mutations) {
    assert.throws(() => decodeTaggedRunnerResults(mutation));
  }
});

test("fresh archive migration creates exactly six disabled durable tables", () => {
  assert.equal(migrationNames.length, 24);
  assert.equal(migrationNames[20], "0021_audit_archive.sql");
  assert.equal(migrationNames[23], "0024_audit_archive_r2_evidence_guard.sql");
  const database = openDatabase();
  try {
    applyThrough(database, "0024_audit_archive_r2_evidence_guard.sql");
    assertFinalArchiveSchema(database);
    assert.deepEqual(
      { ...database.prepare("SELECT * FROM audit_archive_checkpoint").get() },
      {
        id: 1,
        last_archived_at: null,
        last_batch_key: null,
        last_sequence: 0,
        revision: 0,
      },
    );
    assert.equal(
      database.prepare("SELECT count(*) AS count FROM audit_archive_key_sentinel").get()
        .count,
      0,
    );
    integrity(database);
  } finally {
    database.close();
  }
});

test("0021 upgrades a seeded 0020 database with deterministic source order", () => {
  const database = openDatabase();
  try {
    applyThrough(database, "0020_alert_observability.sql");
    const insert = database.prepare(
      `INSERT INTO audit_event (id, event_type, outcome, occurred_at)
       VALUES (?, 'test.archive', 'success', ?)`,
    );
    insert.run("upgrade:z", "2026-07-18T03:00:02.000Z");
    insert.run("upgrade:b", "2026-07-18T03:00:01.000Z");
    insert.run("upgrade:a", "2026-07-18T03:00:01.000Z");

    database.exec(migration("0021_audit_archive.sql"));
    assert.deepEqual(
      database
        .prepare(
          "SELECT sequence, event_id FROM audit_archive_source ORDER BY sequence",
        )
        .all()
        .map((row) => ({ ...row })),
      [
        { event_id: "upgrade:a", sequence: 1 },
        { event_id: "upgrade:b", sequence: 2 },
        { event_id: "upgrade:z", sequence: 3 },
      ],
    );
    insert.run("upgrade:new", "2026-07-18T03:00:03.000Z");
    assert.deepEqual(
      {
        ...database
        .prepare(
          "SELECT sequence, event_id FROM audit_archive_source WHERE event_id = 'upgrade:new'",
        )
        .get(),
      },
      { event_id: "upgrade:new", sequence: 4 },
    );
    integrity(database);
  } finally {
    database.close();
  }
});

test("0021 aborts legacy invalid audit backfill until its parent time is repaired", () => {
  const database = openDatabase();
  const applyArchiveTransaction = () => {
    database.exec("BEGIN");
    try {
      database.exec(migration("0021_audit_archive.sql"));
      database.exec("COMMIT");
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
  };
  try {
    applyThrough(database, "0019_recovery_codes.sql");
    database.prepare(
      `INSERT INTO audit_event (id, event_type, outcome, occurred_at)
       VALUES ('archive:invalid-offset', 'test.archive', 'success',
               '2032-02-04T12:30:00+01:00')`,
    ).run();
    database.exec(migration("0020_alert_observability.sql"));

    assert.throws(
      applyArchiveTransaction,
      /audit archive source requires canonical parent time/,
    );
    assert.equal(
      database.prepare(
        `SELECT count(*) AS count FROM sqlite_schema
          WHERE type = 'table' AND name = 'audit_archive_source'`,
      ).get().count,
      0,
    );

    database.prepare(
      `UPDATE audit_event SET occurred_at = '2032-02-04T11:30:00.000Z'
        WHERE id = 'archive:invalid-offset'`,
    ).run();
    applyArchiveTransaction();
    assert.deepEqual(
      {
        ...database.prepare(
          `SELECT sequence, event_id FROM audit_archive_source
            WHERE event_id = 'archive:invalid-offset'`,
        ).get(),
      },
      { event_id: "archive:invalid-offset", sequence: 1 },
    );
    integrity(database);
  } finally {
    database.close();
  }
});

test("a private 0023 backup upgrades in isolation while its source stays unchanged", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "pgid-archive-preupgrade-"));
  const sourceFilename = path.join(directory, "source-0023.sqlite");
  const backupFilename = path.join(directory, "backup-0023.sqlite");
  const upgradedFilename = path.join(directory, "isolated-0024.sqlite");
  const source = openDatabase(sourceFilename);
  let upgraded;
  try {
    applyThrough(source, "0023_audit_archive_r2_evidence.sql");
    const fixture = seedClaimedArchiveBatch(source);
    const sourceRows = archiveRows(source);
    const sourceSchema = source.prepare(
      `SELECT type, name, tbl_name, sql FROM sqlite_schema
        WHERE name GLOB 'audit_archive_*'
           OR name GLOB 'audit_event_archive_*'
           OR tbl_name GLOB 'audit_archive_*'
        ORDER BY type, name, tbl_name`,
    ).all().map((row) => ({ ...row }));
    assert.equal(
      source.prepare(
        `SELECT count(*) AS count FROM sqlite_schema
          WHERE type = 'trigger'
            AND name = 'audit_archive_attempt_current_r2_evidence_guard'`,
      ).get().count,
      0,
    );
    integrity(source);

    await backup(source, backupFilename);
    chmodSync(backupFilename, 0o600);
    const backupEvidence = {
      bytes: statSync(backupFilename).size,
      mode: statSync(backupFilename).mode & 0o777,
      sha256: sha256File(backupFilename),
    };
    assert.ok(backupEvidence.bytes > 0);
    assert.equal(backupEvidence.mode, 0o600);
    assert.match(backupEvidence.sha256, /^[a-f0-9]{64}$/);

    copyFileSync(backupFilename, upgradedFilename);
    chmodSync(upgradedFilename, 0o600);
    upgraded = openDatabase(upgradedFilename);
    upgraded.exec(migration("0024_audit_archive_r2_evidence_guard.sql"));
    assert.deepEqual(archiveRows(upgraded), sourceRows);
    assertFinalArchiveSchema(upgraded);
    integrity(upgraded);

    const beforeRejected = {
      ...upgraded.prepare(
        "SELECT * FROM audit_archive_attempt WHERE id = ?",
      ).get(fixture.leaseId),
    };
    assert.throws(
      () =>
        upgraded.prepare(
          `UPDATE audit_archive_attempt
              SET outcome = 'corrupt', resulting_status = 'corrupt',
                  r2_version = 'version-upgraded', r2_etag = 'etag-upgraded',
                  r2_stored_sha256 = ?, r2_readback_sha256 = ?,
                  r2_readback_at = ?, error_code = 'r2_readback_mismatch',
                  completed_at = ?
            WHERE id = ?`,
        ).run(
          fixture.objectSha256,
          "f".repeat(64),
          fixture.completedAt,
          fixture.completedAt,
          fixture.leaseId,
        ),
      /current R2 evidence requires observed bytes/,
    );
    assert.deepEqual(
      {
        ...upgraded.prepare(
          "SELECT * FROM audit_archive_attempt WHERE id = ?",
        ).get(fixture.leaseId),
      },
      beforeRejected,
    );
    upgraded.prepare(
      `UPDATE audit_archive_attempt
          SET outcome = 'corrupt', resulting_status = 'corrupt',
              r2_version = 'version-upgraded', r2_etag = 'etag-upgraded',
              r2_observed_bytes = ?, r2_stored_sha256 = ?,
              r2_readback_sha256 = ?, r2_readback_at = ?,
              error_code = 'r2_readback_mismatch', completed_at = ?
        WHERE id = ?`,
    ).run(
      fixture.objectBytes,
      fixture.objectSha256,
      "f".repeat(64),
      fixture.completedAt,
      fixture.completedAt,
      fixture.leaseId,
    );
    assert.deepEqual(
      {
        ...upgraded.prepare(
          `SELECT outcome, error_code, r2_observed_bytes
             FROM audit_archive_attempt WHERE id = ?`,
        ).get(fixture.leaseId),
      },
      {
        error_code: "r2_readback_mismatch",
        outcome: "corrupt",
        r2_observed_bytes: fixture.objectBytes,
      },
    );
    integrity(upgraded);

    assert.deepEqual(archiveRows(source), sourceRows);
    assert.deepEqual(
      source.prepare(
        `SELECT type, name, tbl_name, sql FROM sqlite_schema
          WHERE name GLOB 'audit_archive_*'
             OR name GLOB 'audit_event_archive_*'
             OR tbl_name GLOB 'audit_archive_*'
          ORDER BY type, name, tbl_name`,
      ).all().map((row) => ({ ...row })),
      sourceSchema,
    );
    assert.equal(sha256File(backupFilename), backupEvidence.sha256);
    assert.equal(statSync(backupFilename).size, backupEvidence.bytes);
    assert.equal(statSync(backupFilename).mode & 0o777, 0o600);
    integrity(source);
  } finally {
    upgraded?.close();
    source.close();
    rmSync(directory, { force: true, recursive: true });
  }
});

test("archive ledger survives a private SQLite backup and isolated restore", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "pgid-archive-restore-"));
  const sourceFilename = path.join(directory, "source.sqlite");
  const restoredFilename = path.join(directory, "restored.sqlite");
  let fixture;
  let sourceArchiveRows;
  let sourceEvidenceGuard;
  const source = openDatabase(sourceFilename);
  try {
    applyThrough(source, "0024_audit_archive_r2_evidence_guard.sql");
    fixture = seedClaimedArchiveBatch(source);
    sourceArchiveRows = archiveRows(source);
    sourceEvidenceGuard = evidenceGuardSql(source);
    assertFinalArchiveSchema(source);
    integrity(source);
    await backup(source, restoredFilename);
    chmodSync(restoredFilename, 0o600);
    assert.ok(statSync(restoredFilename).size > 0);
    assert.equal(statSync(restoredFilename).mode & 0o777, 0o600);
    assert.match(sha256File(restoredFilename), /^[a-f0-9]{64}$/);
  } finally {
    source.close();
  }

  const restored = openDatabase(restoredFilename);
  try {
    assert.ok(fixture);
    assert.ok(sourceArchiveRows);
    assert.equal(evidenceGuardSql(restored), sourceEvidenceGuard);
    assertFinalArchiveSchema(restored);
    assert.deepEqual(archiveRows(restored), sourceArchiveRows);
    assert.deepEqual(
      {
        ...restored
        .prepare(
          `SELECT source.sequence, source.event_id, event.subject_id
             FROM audit_archive_source AS source
             JOIN audit_event AS event ON event.id = source.event_id`,
        )
        .get(),
      },
      {
        event_id: "restore:event",
        sequence: 1,
        subject_id: "restore:subject",
      },
    );
    assert.equal(
      restored.prepare("SELECT count(*) AS count FROM audit_archive_key_sentinel").get()
        .count,
      1,
    );
    const before = {
      ...restored.prepare(
        "SELECT * FROM audit_archive_attempt WHERE id = ?",
      ).get(fixture.leaseId),
    };
    assert.throws(
      () =>
        restored.prepare(
          `UPDATE audit_archive_attempt
              SET outcome = 'corrupt', resulting_status = 'corrupt',
                  r2_version = 'version-restored', r2_etag = 'etag-restored',
                  r2_stored_sha256 = ?, r2_readback_sha256 = ?,
                  r2_readback_at = ?, error_code = 'r2_readback_mismatch',
                  completed_at = ?
            WHERE id = ?`,
        ).run(
          fixture.objectSha256,
          "f".repeat(64),
          fixture.completedAt,
          fixture.completedAt,
          fixture.leaseId,
        ),
      /current R2 evidence requires observed bytes/,
    );
    assert.deepEqual(
      {
        ...restored.prepare(
          "SELECT * FROM audit_archive_attempt WHERE id = ?",
        ).get(fixture.leaseId),
      },
      before,
    );
    restored.prepare(
      `UPDATE audit_archive_attempt
          SET outcome = 'corrupt', resulting_status = 'corrupt',
              r2_version = 'version-restored', r2_etag = 'etag-restored',
              r2_observed_bytes = ?, r2_stored_sha256 = ?,
              r2_readback_sha256 = ?, r2_readback_at = ?,
              error_code = 'r2_readback_mismatch', completed_at = ?
        WHERE id = ?`,
    ).run(
      fixture.objectBytes,
      fixture.objectSha256,
      "f".repeat(64),
      fixture.completedAt,
      fixture.completedAt,
      fixture.leaseId,
    );
    assert.deepEqual(
      {
        ...restored.prepare(
          `SELECT outcome, error_code, r2_observed_bytes
             FROM audit_archive_attempt WHERE id = ?`,
        ).get(fixture.leaseId),
      },
      {
        error_code: "r2_readback_mismatch",
        outcome: "corrupt",
        r2_observed_bytes: fixture.objectBytes,
      },
    );
    integrity(restored);
  } finally {
    restored.close();
    rmSync(directory, { force: true, recursive: true });
  }
});

test("normal local migration runner applies 0024 once and then no-ops", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "pgid-archive-runner-"));
  const projectDirectory = path.join(directory, "project");
  try {
    const fixtureMigrations = createMigrationRunnerProject(
      projectDirectory,
      migrationNames.slice(0, 23),
    );
    applyAllMigrations(projectDirectory);
    executeD1(
      projectDirectory,
      `INSERT INTO audit_event
        (id, event_type, outcome, metadata_json, occurred_at)
       VALUES ('runner:event', 'test.archive.runner', 'success',
               '{"kind":"runner_history"}', '2026-07-18T06:00:00.000Z');
       INSERT INTO audit_archive_key_sentinel
        (key_version, domain, fingerprint_ref, fingerprint_hash_version, created_at)
       VALUES ('v1', 'pgid.audit_archive_kek_fingerprint.v1',
               '${"A".repeat(43)}', 1, '2026-07-18T06:00:01.000Z');`,
    );
    const beforeUpgrade = runnerSnapshot(projectDirectory);
    assert.equal(beforeUpgrade.ledger.length, 23);
    assert.deepEqual(beforeUpgrade.ledger.at(-1), {
      id: 23,
      name: "0023_audit_archive_r2_evidence.sql",
    });
    assert.deepEqual(beforeUpgrade.quickCheck, [["ok"]]);
    assert.deepEqual(beforeUpgrade.foreignKeys, []);

    copyFileSync(
      path.join(migrationsDirectory, "0024_audit_archive_r2_evidence_guard.sql"),
      path.join(fixtureMigrations, "0024_audit_archive_r2_evidence_guard.sql"),
    );
    applyAllMigrations(projectDirectory);
    const afterFirstApply = runnerSnapshot(projectDirectory);
    assert.equal(afterFirstApply.ledger.length, 24);
    assert.deepEqual(afterFirstApply.ledger.at(-1), {
      id: 24,
      name: "0024_audit_archive_r2_evidence_guard.sql",
    });
    assert.deepEqual(afterFirstApply.quickCheck, [["ok"]]);
    assert.deepEqual(afterFirstApply.foreignKeys, []);
    assert.deepEqual(afterFirstApply.rows, beforeUpgrade.rows);
    assert.equal(
      afterFirstApply.archiveHistorySha256,
      beforeUpgrade.archiveHistorySha256,
    );
    assert.deepEqual(
      afterFirstApply.ledger.filter(
        ({ name }) => name === "0024_audit_archive_r2_evidence_guard.sql",
      ),
      [{ id: 24, name: "0024_audit_archive_r2_evidence_guard.sql" }],
    );
    assertRunnerFinalArchiveSchema(afterFirstApply);

    applyAllMigrations(projectDirectory);
    const afterSecondApply = runnerSnapshot(projectDirectory);
    assert.deepEqual(afterSecondApply, afterFirstApply);
    assert.deepEqual(
      afterSecondApply.ledger.filter(
        ({ name }) => name === "0024_audit_archive_r2_evidence_guard.sql",
      ),
      [{ id: 24, name: "0024_audit_archive_r2_evidence_guard.sql" }],
    );
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("normal local migration runner preserves recovered 0001-0005", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "pgid-applied-runner-"));
  const projectDirectory = path.join(directory, "project");
  const expectedLedger = migrationNames.map((name, index) => ({
    id: index + 1,
    name,
  }));
  try {
    const fixtureMigrations = createMigrationRunnerProject(
      projectDirectory,
      migrationNames.slice(0, 5),
    );
    applyAllMigrations(projectDirectory);
    assert.deepEqual(
      runnerQueryRows(
        projectDirectory,
        "SELECT id, name FROM d1_migrations ORDER BY id",
      ),
      expectedLedger.slice(0, 5),
    );

    executeD1(
      projectDirectory,
      `INSERT INTO oauthClient (id, clientId, redirectUris)
       VALUES ('runner-client-row', 'runner-client', '["https://rp.example/callback"]');
       INSERT INTO oauthConsent
        (id, clientId, userId, referenceId, scopes, createdAt, updatedAt)
       VALUES
        ('runner-consent-a', 'runner-client', NULL, 'runner-reference',
         '["openid"]', '2026-07-15 06:58:00', '2026-07-15 06:58:00'),
        ('runner-consent-b', 'runner-client', NULL, 'runner-reference',
         '["openid","email"]', '2026-07-15 06:59:00', '2026-07-15 06:59:00');`,
    );
    const before = incrementalRunnerSnapshot(projectDirectory);
    assert.equal(before.consents.length, 2);

    for (const name of migrationNames.slice(5)) {
      copyFileSync(
        path.join(migrationsDirectory, name),
        path.join(fixtureMigrations, name),
      );
    }
    applyAllMigrations(projectDirectory);
    const afterFirstApply = incrementalRunnerSnapshot(projectDirectory);
    assert.deepEqual(afterFirstApply.consents, before.consents);
    assert.deepEqual(afterFirstApply.ledger, expectedLedger);
    assert.deepEqual(afterFirstApply.quickCheck, [{ quick_check: "ok" }]);
    assert.deepEqual(afterFirstApply.foreignKeys, []);

    applyAllMigrations(projectDirectory);
    assert.deepEqual(
      incrementalRunnerSnapshot(projectDirectory),
      afterFirstApply,
    );
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("archive lease predicates retain canonical millisecond boundaries", () => {
  const source = migration("0021_audit_archive.sql");
  assert.equal(source.match(/'\+0 seconds'/g)?.length, 30);
  assert.doesNotMatch(
    source,
    /strftime\('%Y-%m-%dT%H:%M:%fZ', "[a-z_]+"\)/,
  );
  assert.doesNotMatch(source, /unixepoch\(NEW\.|unixepoch\(OLD\./);
  assert.match(
    source,
    /NEW\."completed_at" >= batch\."lease_expires_at"/,
  );
  assert.match(
    source,
    /NEW\."completed_at" < batch\."lease_expires_at"/,
  );
  assert.match(
    source,
    /NEW\."lease_expires_at" <= strftime\([\s\S]*?'\+300 seconds'/,
  );
  assert.match(
    source,
    /"completed_at" IS NOT NULL AND "next_attempt_at" >= "completed_at"/,
  );
  for (const field of ["r2_version", "r2_etag"]) {
    for (const codePoint of [0, 10, 13]) {
      assert.equal(
        source.match(
          new RegExp(`instr\\("${field}", char\\(${codePoint}\\)\\) = 0`, "g"),
        )?.length,
        2,
      );
    }
  }
  assert.match(
    source,
    /SELECT 1 FROM "audit_archive_batch"[\s\S]*?"batch_key" = NEW\."batch_key"/,
  );
});

test("fresh 0021 renews only the same live lease without another attempt", () => {
  const database = openDatabase();
  try {
    applyThrough(database, "0021_audit_archive.sql");
    const occurredAt = "2026-07-18T05:00:00.000Z";
    const createdAt = "2026-07-18T05:00:01.000Z";
    const eventId = "node.archive.renew";
    database
      .prepare(
        `INSERT INTO audit_event (id, event_type, outcome, occurred_at)
         VALUES (?, 'test.archive', 'success', ?)`,
      )
      .run(eventId, occurredAt);
    const { sequence } = database
      .prepare("SELECT sequence FROM audit_archive_source WHERE event_id = ?")
      .get(eventId);
    database
      .prepare(
        `INSERT INTO audit_archive_key_sentinel
          (key_version, domain, fingerprint_ref, fingerprint_hash_version,
           created_at)
         VALUES ('v1', 'pgid.audit_archive_kek_fingerprint.v1', ?, 1, ?)`,
      )
      .run("A".repeat(43), createdAt);

    const batchKey = `${"B".repeat(42)}E`;
    const objectSha256 = "1".repeat(64);
    const plaintextSha256 = "2".repeat(64);
    const objectBytes = new Uint8Array([1, 2, 3]);
    const objectKey = `audit/v1/${String(sequence).padStart(16, "0")}-${String(
      sequence,
    ).padStart(16, "0")}/${objectSha256}.pgid-audit`;
    const record = {
      actorRef: null,
      actorRefHashVersion: null,
      actorUserId: null,
      clientId: null,
      eventId,
      eventType: "test.archive",
      ipHash: null,
      metadataJson: null,
      occurredAt,
      outcome: "success",
      sequence,
      sessionId: null,
      subjectId: null,
      userAgentHash: null,
    };
    const canonicalRecord = JSON.stringify(record);
    const plaintextBytes = Buffer.byteLength(
      JSON.stringify({
        contract: "pgid-audit-records-v1",
        records: [record],
        schemaVersion: 1,
      }),
    );
    const manifest = {
      batchGeneration: 1,
      checkpointFromSequence: 0,
      contentType: "application/vnd.pg72.pgid-audit-archive+json",
      contract: "pgid-audit-archive-v1",
      createdAt,
      eventCount: 1,
      firstSequence: sequence,
      keyVersion: "v1",
      lastSequence: sequence,
      objectBytes: objectBytes.byteLength,
      objectKey,
      objectSha256,
      plaintextSha256,
      schemaVersion: 1,
    };

    database.exec("BEGIN");
    try {
      database
        .prepare(
          `INSERT INTO audit_archive_batch_item
            (batch_key, ordinal, source_sequence, event_id, event_type,
             actor_user_id, actor_ref, actor_ref_hash_version, subject_id,
             client_id, session_id, outcome, ip_hash, user_agent_hash,
             metadata_json, occurred_at, canonical_record_json,
             canonical_record_bytes)
           VALUES (?, 1, ?, ?, 'test.archive', NULL, NULL, NULL, NULL,
                   NULL, NULL, 'success', NULL, NULL, NULL, ?, ?, ?)`,
        )
        .run(
          batchKey,
          sequence,
          eventId,
          occurredAt,
          canonicalRecord,
          Buffer.byteLength(canonicalRecord),
        );
      database
        .prepare(
          `INSERT INTO audit_archive_batch
            (batch_key, batch_generation, checkpoint_revision,
             checkpoint_from_sequence, schema_version, contract, manifest_json,
             first_sequence, last_sequence, event_count, plaintext_bytes,
             plaintext_sha256, key_version, content_type, object_key,
             object_bytes, object_sha256, encrypted_envelope, status,
             dispatch_generation, attempts, next_attempt_at, lease_id,
             lease_expires_at, r2_version, r2_etag, r2_readback_sha256,
             r2_readback_at, archived_at, envelope_gc_at, last_error_code,
             manual_replay_audit_id, created_at, updated_at)
           VALUES (?, 1, 0, 0, 1, 'pgid-audit-archive-v1', ?, ?, ?, 1, ?, ?,
                   'v1', 'application/vnd.pg72.pgid-audit-archive+json', ?, ?, ?,
                   ?, 'pending', 1, 0, ?, NULL, NULL, NULL, NULL, NULL, NULL,
                   NULL, NULL, NULL, NULL, ?, ?)`,
        )
        .run(
          batchKey,
          JSON.stringify(manifest),
          sequence,
          sequence,
          plaintextBytes,
          plaintextSha256,
          objectKey,
          objectBytes.byteLength,
          objectSha256,
          objectBytes,
          createdAt,
          createdAt,
          createdAt,
        );
      database.exec("COMMIT");
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }

    const leaseId = `${"C".repeat(42)}E`;
    database
      .prepare(
        `UPDATE audit_archive_batch
            SET status = 'processing', attempts = 1, next_attempt_at = NULL,
                lease_id = ?, lease_expires_at = ?, updated_at = ?
          WHERE batch_key = ?`,
      )
      .run(
        leaseId,
        "2026-07-18T05:03:00.000Z",
        "2026-07-18T05:00:02.000Z",
        batchKey,
      );
    const renewed = database
      .prepare(
        `UPDATE audit_archive_batch
            SET lease_expires_at = ?, updated_at = ?
          WHERE batch_key = ? AND lease_id = ?`,
      )
      .run(
        "2026-07-18T05:04:30.000Z",
        "2026-07-18T05:01:30.000Z",
        batchKey,
        leaseId,
      );
    assert.equal(renewed.changes, 1);
    assert.equal(
      database.prepare("SELECT count(*) AS count FROM audit_archive_attempt").get()
        .count,
      1,
    );
    assert.deepEqual(
      {
        ...database
        .prepare(
          `SELECT status, attempts, lease_id, lease_expires_at, updated_at
             FROM audit_archive_batch WHERE batch_key = ?`,
        )
        .get(batchKey),
      },
      {
        attempts: 1,
        lease_expires_at: "2026-07-18T05:04:30.000Z",
        lease_id: leaseId,
        status: "processing",
        updated_at: "2026-07-18T05:01:30.000Z",
      },
    );
    assert.throws(() =>
      database
        .prepare(
          `UPDATE audit_archive_batch
              SET lease_expires_at = ?, updated_at = ?
            WHERE batch_key = ?`,
        )
        .run(
          "2026-07-18T05:05:00.000Z",
          "2026-07-18T05:04:30.000Z",
          batchKey,
        )
    );
    assert.throws(() =>
      database
        .prepare(
          `UPDATE audit_archive_batch
              SET lease_id = ?, lease_expires_at = ?, updated_at = ?
            WHERE batch_key = ?`,
        )
        .run(
          `${"D".repeat(42)}E`,
          "2026-07-18T05:05:00.000Z",
          "2026-07-18T05:02:00.000Z",
          batchKey,
        )
    );
    integrity(database);
  } finally {
    database.close();
  }
});
