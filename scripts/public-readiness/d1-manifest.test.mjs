import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createContinuityCryptoFixtures,
  renderContinuitySeed,
} from "./crypto-fixtures.mjs";
import {
  D1_CONSISTENCY_CHECK_SQL,
  INTEGRATED_MIGRATION_LEDGER,
  assertEquivalentD1,
  assertIntegratedMigrationLedger,
  classifiedManifestStep,
  expectedMigrationHead,
  expectedIntegratedMigrationLedger,
  expectedMigrationLedger,
  isApplicationSchemaRow,
  normalizeMigrationLedgerRows,
  normalizeSingleRowCount,
  quickCheckPassed,
  trustedTableCountSql,
} from "./d1-manifest.mjs";
import { ssoRoot } from "./local-runtime.mjs";

function sqlite(database, sql) {
  const result = spawnSync("sqlite3", [database], {
    encoding: "utf8",
    input: sql,
    maxBuffer: 10 * 1024 * 1024,
  });
  assert.equal(result.status, 0, "synthetic SQLite verification failed");
  return result.stdout.trim();
}

test("renders a private synthetic fixture through every integrated migration", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "pgid-continuity-seed-"));
  const database = path.join(directory, "continuity.sqlite");
  const rendered = path.join(directory, "continuity-seed.sql");
  try {
    for (const migration of readdirSync(path.join(ssoRoot, "migrations"))
      .filter((name) => /^\d{4}_.+\.sql$/.test(name))
      .sort()) {
      sqlite(database, readFileSync(path.join(ssoRoot, "migrations", migration), "utf8"));
    }
    const fixture = await createContinuityCryptoFixtures(
      "synthetic-continuity-unit-secret-32-characters",
    );
    renderContinuitySeed(
      new URL("./fixtures/continuity-seed.sql", import.meta.url),
      rendered,
      fixture,
    );
    assert.equal(statSync(rendered).mode & 0o777, 0o600);
    sqlite(database, readFileSync(rendered, "utf8"));

    assert.equal(sqlite(database, "PRAGMA integrity_check;"), "ok");
    assert.equal(sqlite(database, "PRAGMA foreign_key_check;"), "");
    assert.equal(
      sqlite(
        database,
        `SELECT COUNT(*) FROM sqlite_schema
          WHERE type = 'table'
            AND name IN (
              'alert_state', 'security_alert', 'alert_outbox',
              'alert_delivery_attempt', 'alert_runtime_status'
            );`,
      ),
      "5",
    );
    assert.equal(
      sqlite(
        database,
        `SELECT COUNT(*) FROM sqlite_schema
          WHERE type = 'index' AND name = 'alert_outbox_due_idx';`,
      ),
      "1",
    );
    assert.equal(
      sqlite(
        database,
        `SELECT COUNT(*) FROM sqlite_schema
          WHERE name = 'audit_event_sequence';`,
      ),
      "0",
    );
    sqlite(
      database,
      `INSERT INTO audit_event (id, event_type, outcome, occurred_at)
       VALUES (
         '99999999-0000-4000-8000-000000000001',
         'observability.migration_test',
         'success',
         '2026-07-17T10:00:00.000Z'
       );
       DELETE FROM audit_event
        WHERE id = '99999999-0000-4000-8000-000000000001';`,
    );
    assert.equal(
      sqlite(
        database,
        `SELECT COUNT(*) FROM audit_event
          WHERE id = '99999999-0000-4000-8000-000000000001';`,
      ),
      "0",
    );
    assert.equal(
      sqlite(
        database,
        `SELECT
          (SELECT COUNT(*) FROM user) || '|' ||
          (SELECT COUNT(*) FROM session) || '|' ||
          (SELECT COUNT(*) FROM passkey) || '|' ||
          (SELECT COUNT(*) FROM oauthClient) || '|' ||
          (SELECT COUNT(*) FROM oauthConsent) || '|' ||
          (SELECT COUNT(*) FROM jwks) || '|' ||
          (SELECT COUNT(*) FROM rp_session_client);`,
      ),
      "1|2|1|1|1|2|1",
    );
    assert.equal(
      sqlite(database, "SELECT length(clientSecret) FROM oauthClient;"),
      "43",
    );
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("requires exact manifest and internal-record equivalence", () => {
  const manifest = {
    foreignKeysOk: true,
    integrityOk: true,
    migrationLedger: {
      count: 2,
      head: "0002_second.sql",
      names: ["0001_first.sql", "0002_second.sql"],
      sha256: "b".repeat(64),
    },
    rowCounts: { user: 1 },
    schemaSha256: "a".repeat(64),
  };
  const records = { user_record: { id: "synthetic-subject" } };
  assert.doesNotThrow(() =>
    assertEquivalentD1(manifest, structuredClone(manifest), records, structuredClone(records)),
  );
  assert.throws(() =>
    assertEquivalentD1(
      manifest,
      { ...manifest, rowCounts: { user: 2 } },
      records,
      records,
    ),
  );
});

test("derives the complete migration ledger from the integrated source sequence", () => {
  const migrationsDirectory = path.join(ssoRoot, "migrations");
  const expectedNames = readdirSync(migrationsDirectory)
    .filter((name) => /^\d{4}_[a-z0-9_]+\.sql$/.test(name))
    .sort();
  const ledger = expectedMigrationLedger(migrationsDirectory);
  assert.deepEqual(ledger.names, expectedNames);
  assert.equal(ledger.count, expectedNames.length);
  assert.equal(ledger.head, expectedNames.at(-1));
  assert.match(ledger.sha256, /^[a-f0-9]{64}$/);
  assert.equal(expectedMigrationHead(migrationsDirectory), ledger.head);
  assert.deepEqual(
    expectedIntegratedMigrationLedger(migrationsDirectory),
    ledger,
  );
  assert.deepEqual(
    { count: ledger.count, head: ledger.head },
    INTEGRATED_MIGRATION_LEDGER,
  );
});

test("integrated migration proof requires exact 0020 count and head", () => {
  assert.doesNotThrow(() =>
    assertIntegratedMigrationLedger({
      count: 20,
      head: "0020_alert_observability.sql",
    }),
  );
  assert.throws(() =>
    assertIntegratedMigrationLedger({
      count: 18,
      head: "0018_global_logout.sql",
    }),
  );
  assert.throws(() =>
    assertIntegratedMigrationLedger({
      count: 20,
      head: "0020_lookalike.sql",
    }),
  );
});

test("migration source ledger rejects gaps, duplicate numbers, malformed names, and links", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "pgid-migration-ledger-"));
  const writeMigration = (name) => writeFileSync(path.join(directory, name), "SELECT 1;\n");
  try {
    writeMigration("0001_first.sql");
    writeMigration("0002_second.sql");
    assert.equal(expectedMigrationLedger(directory).count, 2);

    writeMigration("0004_gap.sql");
    assert.throws(() => expectedMigrationLedger(directory), /gap or out-of-order/);
    rmSync(path.join(directory, "0004_gap.sql"));

    writeMigration("0002_duplicate.sql");
    assert.throws(() => expectedMigrationLedger(directory), /duplicate numbers/);
    rmSync(path.join(directory, "0002_duplicate.sql"));

    writeMigration("2_malformed.sql");
    assert.throws(() => expectedMigrationLedger(directory), /invalid migration filename/);
    rmSync(path.join(directory, "2_malformed.sql"));

    writeMigration("0003_empty.sql");
    writeFileSync(path.join(directory, "0003_empty.sql"), "");
    assert.throws(() => expectedMigrationLedger(directory), /must not be empty/);
    rmSync(path.join(directory, "0003_empty.sql"));

    rmSync(path.join(directory, "0002_second.sql"));
    symlinkSync(path.join(directory, "0001_first.sql"), path.join(directory, "0002_link.sql"));
    assert.throws(() => expectedMigrationLedger(directory), /regular migration file/);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("D1 ledger normalization requires every exact ordered migration row", () => {
  const rows = [
    { id: 1, name: "0001_first.sql" },
    { id: 2, name: "0002_second.sql" },
    { id: 3, name: "0003_third.sql" },
  ];
  const ledger = normalizeMigrationLedgerRows(rows);
  assert.deepEqual(ledger.names, rows.map(({ name }) => name));
  assert.equal(ledger.count, 3);
  assert.equal(ledger.head, "0003_third.sql");
  assert.throws(() => normalizeMigrationLedgerRows([]), /empty/);
  assert.throws(
    () => normalizeMigrationLedgerRows([rows[0], rows[2]]),
    /ID gap or duplicate/,
  );
  assert.throws(
    () => normalizeMigrationLedgerRows([{ ...rows[0], extra: true }]),
    /unexpected columns/,
  );
  assert.throws(
    () => normalizeMigrationLedgerRows([{ id: "1", name: rows[0].name }]),
    /must be an integer/,
  );
  assert.throws(
    () => normalizeMigrationLedgerRows([rows[0], { id: 2, name: rows[0].name }]),
    /filename gap or duplicate/,
  );
});

test("manifest diagnostics expose only a fixed class", () => {
  const marker = "raw-d1-diagnostic-must-not-escape";
  assert.throws(
    () =>
      classifiedManifestStep("D1SchemaQueryError", () => {
        throw new Error(marker);
      }),
    (error) => {
      assert.equal(error.name, "D1SchemaQueryError");
      assert.equal(error.message, "closed manifest failure");
      assert.equal(error.message.includes(marker), false);
      assert.equal(error.cause, undefined);
      return true;
    },
  );
  assert.throws(
    () =>
      classifiedManifestStep("D1RowCountTable07Error", () => {
        throw new Error(marker);
      }),
    (error) => {
      assert.equal(error.name, "D1RowCountTable07Error");
      assert.equal(error.message, "closed manifest failure");
      return true;
    },
  );
  assert.throws(
    () => classifiedManifestStep("D1RowCountTable123Error", () => true),
    (error) => error?.name === "AssertionError",
  );
});

test("row-count normalization requires an exact schema-shaped result", () => {
  assert.equal(normalizeSingleRowCount([{ row_count: 2 }]), 2);
  assert.equal(normalizeSingleRowCount([{ row_count: "2" }]), 2);
  assert.throws(
    () => normalizeSingleRowCount([{ account: 2 }]),
    (error) => error?.name === "D1RowCountColumnsError",
  );
  assert.throws(
    () => normalizeSingleRowCount([{ row_count: 2, unexpected: 0 }]),
    (error) => error?.name === "D1RowCountColumnsError",
  );
  assert.throws(
    () => normalizeSingleRowCount([{ row_count: -1 }]),
    (error) => error?.name === "D1RowCountValueError",
  );
  assert.throws(
    () => normalizeSingleRowCount([]),
    (error) => error?.name === "D1RowCountCardinalityError",
  );
});

test("row-count SQL accepts only trusted parameter-free identifiers", () => {
  assert.equal(
    trustedTableCountSql("oauthAccessToken"),
    "SELECT COUNT(*) AS row_count FROM oauthAccessToken",
  );
  for (const value of [
    "account table",
    "account;DELETE",
    'account"',
    "account--comment",
    "account.table",
  ]) {
    assert.throws(() => trustedTableCountSql(value));
  }
});

test("application schema excludes exact D1 internal prefixes only", () => {
  for (const value of ["_cf_METADATA", "_cf_internal", "sqlite_sequence"]) {
    assert.equal(
      isApplicationSchemaRow({ name: value, tbl_name: value }),
      false,
    );
  }
  assert.equal(
    isApplicationSchemaRow({
      name: "d1_migrations",
      tbl_name: "d1_migrations",
    }),
    false,
  );
  for (const value of ["_cfMetadata", "_cf", "cf_METADATA", "app_cf_data"]) {
    assert.equal(
      isApplicationSchemaRow({ name: value, tbl_name: value }),
      true,
    );
  }
  assert.equal(
    isApplicationSchemaRow({ name: "app_index", tbl_name: "_cf_METADATA" }),
    false,
  );
});

test("D1 consistency uses the supported quick-check contract exactly", () => {
  assert.equal(D1_CONSISTENCY_CHECK_SQL, "PRAGMA quick_check");
  assert.equal(quickCheckPassed([{ quick_check: "ok" }]), true);
  assert.equal(quickCheckPassed([{ integrity_check: "ok" }]), false);
  assert.equal(quickCheckPassed([{ quick_check: "OK" }]), false);
  assert.equal(quickCheckPassed([{ quick_check: "ok", extra: "ok" }]), false);
  assert.equal(quickCheckPassed([]), false);
});
