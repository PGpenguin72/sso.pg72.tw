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
  assert.equal(migrationNames.length, 21);
  assert.equal(migrationNames.at(-1), "0021_audit_archive.sql");
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
  assert.equal(source.match(/'\+0 seconds'/g)?.length, 28);
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
});
