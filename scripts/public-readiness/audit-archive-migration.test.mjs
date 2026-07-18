import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync, backup } from "node:sqlite";
import test from "node:test";
import { fileURLToPath } from "node:url";

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

test("fresh archive migration creates exactly six disabled durable tables", () => {
  assert.equal(migrationNames[20], "0021_audit_archive.sql");
  const database = openDatabase();
  try {
    applyThrough(database, "0021_audit_archive.sql");
    assert.deepEqual(
      database
        .prepare(
          `SELECT name FROM sqlite_schema
            WHERE type = 'table' AND name GLOB 'audit_archive_*'
            ORDER BY name`,
        )
        .all()
        .map(({ name }) => name),
      [
        "audit_archive_attempt",
        "audit_archive_batch",
        "audit_archive_batch_item",
        "audit_archive_checkpoint",
        "audit_archive_key_sentinel",
        "audit_archive_source",
      ],
    );
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

test("archive ledger survives a private SQLite backup and isolated restore", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "pgid-archive-restore-"));
  const sourceFilename = path.join(directory, "source.sqlite");
  const restoredFilename = path.join(directory, "restored.sqlite");
  const source = openDatabase(sourceFilename);
  try {
    applyThrough(source, "0021_audit_archive.sql");
    source
      .prepare(
        `INSERT INTO audit_event
          (id, event_type, subject_id, outcome, metadata_json, occurred_at)
         VALUES ('restore:event', 'test.archive', 'restore:subject', 'success',
                 '{"kind":"restore_test"}', '2026-07-18T04:00:00.000Z')`,
      )
      .run();
    source
      .prepare(
        `INSERT INTO audit_archive_key_sentinel
          (key_version, domain, fingerprint_ref, fingerprint_hash_version, created_at)
         VALUES ('v1', 'pgid.audit_archive_kek_fingerprint.v1', ?, 1,
                 '2026-07-18T04:00:01.000Z')`,
      )
      .run("A".repeat(43));
    integrity(source);
    await backup(source, restoredFilename);
  } finally {
    source.close();
  }

  const restored = openDatabase(restoredFilename);
  try {
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
    integrity(restored);
  } finally {
    restored.close();
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
