import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
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

function applyThrough(database, head) {
  for (const name of migrationNames) {
    database.exec(migration(name));
    if (name === head) return;
  }
  throw new Error(`migration head not found: ${head}`);
}

function invalidTimestampPredicate(column) {
  return `NOT (
    typeof("${column}") = 'text'
    AND length("${column}") = 24
    AND strftime(
      '%Y-%m-%dT%H:%M:%fZ', "${column}", '+0 seconds'
    ) IS NOT NULL
    AND strftime(
      '%Y-%m-%dT%H:%M:%fZ', "${column}", '+0 seconds'
    ) = "${column}"
  )`;
}

function integrityQuery(table, index, column) {
  return `SELECT EXISTS (
    SELECT 1 FROM "${table}" INDEXED BY "${index}"
     WHERE ${invalidTimestampPredicate(column)}
     LIMIT 1
  ) AS invalid_timestamp_exists`;
}

function assertCoveringSparsePlan(database, table, index, column) {
  const plan = database.prepare(
    `EXPLAIN QUERY PLAN ${integrityQuery(table, index, column)}`,
  ).all();
  const details = plan.map(({ detail }) => detail).join("\n");
  assert.match(details, new RegExp(`USING COVERING INDEX ${index}`));
  assert.doesNotMatch(details, new RegExp(`SCAN ${table}(?:$|\\s+(?!USING))`));
}

const invalidTimestamps = [
  ["offset", "2032-02-04T12:30:00+01:00"],
  ["far-low", "0001-01-01T00:30:00+01:00"],
  ["far-high", "9998-12-31T23:30:00-01:00"],
  ["bad-calendar", "2025-02-29T00:00:00.000Z"],
  ["numeric", 123456789],
];

test("0020 indexes legacy invalid source times and guards future writes", () => {
  const database = new DatabaseSync(":memory:");
  database.exec("PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = OFF;");
  try {
    applyThrough(database, "0019_recovery_codes.sql");
    const insertAudit = database.prepare(
      `INSERT INTO audit_event (id, event_type, outcome, occurred_at)
       VALUES (?, 'test.time_integrity', 'success', ?)`,
    );
    const insertReport = database.prepare(
      `INSERT INTO oauth_client_report
        (id, client_id, reason, status, created_at)
       VALUES (?, 'time-integrity-client', 'other', 'open', ?)`,
    );
    for (const [id, timestamp] of invalidTimestamps) {
      insertAudit.run(`audit:${id}`, timestamp);
      insertReport.run(`oauth:${id}`, timestamp);
    }

    database.exec(migration("0020_alert_observability.sql"));

    const sources = [
      {
        column: "occurred_at",
        index: "audit_event_invalid_occurred_at_idx",
        prefix: "audit:",
        table: "audit_event",
      },
      {
        column: "created_at",
        index: "oauth_client_report_invalid_created_at_idx",
        prefix: "oauth:",
        table: "oauth_client_report",
      },
    ];
    for (const { column, index, prefix, table } of sources) {
      assert.deepEqual(
        database.prepare(`PRAGMA index_info("${index}")`).all().map((row) => ({
          name: row.name,
          seqno: row.seqno,
        })),
        [{ name: column, seqno: 0 }],
      );
      assert.deepEqual(
        database.prepare(
          `SELECT id FROM "${table}" INDEXED BY "${index}"
            WHERE ${invalidTimestampPredicate(column)} ORDER BY id`,
        ).all().map(({ id }) => id),
        invalidTimestamps.map(([id]) => `${prefix}${id}`).sort(),
      );
      assert.equal(
        database.prepare(integrityQuery(table, index, column)).get()
          .invalid_timestamp_exists,
        1,
      );
      assertCoveringSparsePlan(database, table, index, column);
    }

    assert.throws(
      () => insertAudit.run("audit:future-invalid", invalidTimestamps[0][1]),
      /audit event timestamp must be canonical/,
    );
    assert.throws(
      () => insertReport.run("oauth:future-invalid", invalidTimestamps[0][1]),
      /OAuth report timestamp must be canonical/,
    );
    assert.throws(
      () => database.prepare(
        "UPDATE audit_event SET occurred_at = ? WHERE id = 'audit:offset'",
      ).run(invalidTimestamps[3][1]),
      /audit event timestamp must be canonical/,
    );
    assert.throws(
      () => database.prepare(
        "UPDATE oauth_client_report SET created_at = ? WHERE id = 'oauth:offset'",
      ).run(invalidTimestamps[3][1]),
      /OAuth report timestamp must be canonical/,
    );

    for (const [index, [id]] of invalidTimestamps.entries()) {
      const repaired = new Date(Date.UTC(2032, 0, 1, 0, 0, index)).toISOString();
      database.prepare(
        "UPDATE audit_event SET occurred_at = ? WHERE id = ?",
      ).run(repaired, `audit:${id}`);
      database.prepare(
        "UPDATE oauth_client_report SET created_at = ? WHERE id = ?",
      ).run(repaired, `oauth:${id}`);
    }

    for (const { column, index, table } of sources) {
      assert.equal(
        database.prepare(integrityQuery(table, index, column)).get()
          .invalid_timestamp_exists,
        0,
      );
      assertCoveringSparsePlan(database, table, index, column);
    }
    assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
    assert.deepEqual({ ...database.prepare("PRAGMA quick_check").get() }, {
      quick_check: "ok",
    });
  } finally {
    database.close();
  }
});
