import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

import { runWrangler } from "./local-runtime.mjs";

const APPLICATION_TABLE_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MIGRATION_FILENAME_PATTERN = /^\d{4}_[a-z0-9_]+\.sql$/;
export const D1_CONSISTENCY_CHECK_SQL = "PRAGMA quick_check";
const MANIFEST_ERROR_NAMES = new Set([
  "D1ForeignKeyError",
  "D1IntegrityError",
  "D1MigrationLedgerError",
  "D1RowCountCardinalityError",
  "D1RowCountColumnsError",
  "D1RowCountError",
  "D1RowCountQueryError",
  "D1RowCountValueError",
  "D1SchemaHashError",
  "D1SchemaQueryError",
  "D1TablePolicyError",
]);
const ROW_COUNT_TABLE_ERROR_PATTERN = /^D1RowCountTable\d{2}Error$/;

function isManifestErrorName(errorName) {
  return (
    MANIFEST_ERROR_NAMES.has(errorName) ||
    ROW_COUNT_TABLE_ERROR_PATTERN.test(errorName)
  );
}

export function classifiedManifestStep(errorName, operation) {
  assert.ok(isManifestErrorName(errorName));
  assert.equal(typeof operation, "function");
  try {
    return operation();
  } catch (cause) {
    if (cause instanceof Error && isManifestErrorName(cause.name)) {
      throw cause;
    }
    const error = new Error("closed manifest failure");
    error.name = errorName;
    throw error;
  }
}

export function normalizeSingleRowCount(rows) {
  if (rows.length !== 1) {
    const error = new Error("closed row-count cardinality failure");
    error.name = "D1RowCountCardinalityError";
    throw error;
  }
  const row = rows[0];
  try {
    assert.deepEqual(Object.keys(row), ["row_count"]);
  } catch {
    const error = new Error("closed row-count column failure");
    error.name = "D1RowCountColumnsError";
    throw error;
  }
  const count = Number(row.row_count);
  if (!Number.isSafeInteger(count) || count < 0) {
    const error = new Error("closed row-count value failure");
    error.name = "D1RowCountValueError";
    throw error;
  }
  return count;
}

export function trustedTableCountSql(table) {
  assert.match(table, APPLICATION_TABLE_PATTERN);
  return `SELECT COUNT(*) AS row_count FROM ${table}`;
}

export function quickCheckPassed(rows) {
  return (
    rows.length === 1 &&
    Object.keys(rows[0]).length === 1 &&
    rows[0].quick_check === "ok"
  );
}

export function isApplicationSchemaRow({ name, tbl_name: table }) {
  for (const value of [name, table]) {
    if (
      value === "d1_migrations" ||
      value.startsWith("sqlite_") ||
      value.startsWith("_cf_")
    ) {
      return false;
    }
  }
  return true;
}

export function expectedMigrationHead(migrationsDirectory) {
  return expectedMigrationLedger(migrationsDirectory).head;
}

export const INTEGRATED_MIGRATION_LEDGER = Object.freeze({
  count: 24,
  head: "0024_audit_archive_r2_evidence_guard.sql",
});

export function assertIntegratedMigrationLedger(ledger) {
  assert.equal(
    ledger.count,
    INTEGRATED_MIGRATION_LEDGER.count,
    "integrated migration ledger count drifted",
  );
  assert.equal(
    ledger.head,
    INTEGRATED_MIGRATION_LEDGER.head,
    "integrated migration ledger head drifted",
  );
  return ledger;
}

export function expectedIntegratedMigrationLedger(migrationsDirectory) {
  return assertIntegratedMigrationLedger(expectedMigrationLedger(migrationsDirectory));
}

function canonicalMigrationLedger(names) {
  return {
    count: names.length,
    head: names.at(-1),
    names,
    sha256: createHash("sha256").update(JSON.stringify(names)).digest("hex"),
  };
}

export function expectedMigrationLedger(migrationsDirectory) {
  const entries = readdirSync(migrationsDirectory).sort();
  const sqlEntries = entries.filter((name) => name.endsWith(".sql"));
  for (const name of sqlEntries) {
    assert.match(name, MIGRATION_FILENAME_PATTERN, `invalid migration filename ${name}`);
    const stat = lstatSync(path.join(migrationsDirectory, name));
    assert.equal(
      stat.isFile(),
      true,
      `${name} must be a regular migration file`,
    );
    assert.ok(stat.size > 0, `${name} must not be empty`);
  }
  const migrations = sqlEntries;
  assert.ok(migrations.length > 0, "migration directory is empty");
  assert.equal(
    new Set(migrations.map((name) => name.slice(0, 4))).size,
    migrations.length,
    "migration sequence contains duplicate numbers",
  );
  for (const migration of migrations) {
    assert.equal(
      path.basename(migration),
      migration,
      "migration filename must not escape its directory",
    );
  }
  migrations.forEach((migration, index) => {
    assert.equal(
      Number(migration.slice(0, 4)),
      index + 1,
      "migration sequence contains a gap or out-of-order number",
    );
  });
  return canonicalMigrationLedger(migrations);
}

export function normalizeMigrationLedgerRows(rows) {
  assert.ok(rows.length > 0, "D1 migration ledger is empty");
  const names = rows.map((row, index) => {
    assert.deepEqual(
      Object.keys(row),
      ["id", "name"],
      "D1 migration ledger row has unexpected columns",
    );
    assert.ok(Number.isSafeInteger(row.id), "D1 migration ID must be an integer");
    assert.equal(row.id, index + 1, "D1 migration ledger contains an ID gap or duplicate");
    assert.match(row.name, MIGRATION_FILENAME_PATTERN);
    assert.equal(
      Number(row.name.slice(0, 4)),
      index + 1,
      "D1 migration ledger contains a filename gap or duplicate",
    );
    return row.name;
  });
  assert.equal(new Set(names).size, names.length, "D1 migration ledger repeats a name");
  return canonicalMigrationLedger(names);
}

function parseWranglerJson(output) {
  const withoutAnsi = output.replace(/\u001b\[[0-9;]*m/g, "");
  const start = withoutAnsi.indexOf("[");
  assert.ok(start >= 0, "Wrangler did not return JSON output");
  const parsed = JSON.parse(withoutAnsi.slice(start));
  assert.ok(Array.isArray(parsed) && parsed.length > 0, "Wrangler JSON result was empty");
  for (const result of parsed) {
    assert.equal(result.success, true, "Wrangler D1 statement failed");
  }
  return parsed;
}

export function executeD1(projectDirectory, sql) {
  const output = runWrangler(
    projectDirectory,
    ["d1", "execute", "PG72_ID_DB", "--local", "--json", "--command", sql],
    { label: "local D1 query" },
  );
  return parseWranglerJson(output);
}

export function queryRows(projectDirectory, sql) {
  return executeD1(projectDirectory, sql).flatMap((result) => result.results ?? []);
}

export function applyAllMigrations(projectDirectory) {
  runWrangler(
    projectDirectory,
    ["d1", "migrations", "apply", "PG72_ID_DB", "--local"],
    { label: "local D1 migrations" },
  );
}

export function executeD1File(projectDirectory, filename, label = "local D1 file") {
  runWrangler(
    projectDirectory,
    ["d1", "execute", "PG72_ID_DB", "--local", "--file", filename],
    { label },
  );
}

export function exportD1(projectDirectory, filename) {
  runWrangler(
    projectDirectory,
    [
      "d1",
      "export",
      "PG72_ID_DB",
      "--local",
      "--output",
      filename,
      "--skip-confirmation",
    ],
    { label: "local D1 export" },
  );
  return {
    bytes: statSync(filename).size,
    sha256: createHash("sha256").update(readFileSync(filename)).digest("hex"),
  };
}

function schemaHash(rows) {
  const canonical = rows.map(({ name, sql, tbl_name, type }) => ({
    name,
    sql,
    table: tbl_name,
    type,
  }));
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}

export function collectD1Manifest(projectDirectory) {
  const schemaRows = classifiedManifestStep("D1SchemaQueryError", () =>
    queryRows(
      projectDirectory,
      `SELECT type, name, tbl_name, sql
         FROM sqlite_schema
        WHERE sql IS NOT NULL
        ORDER BY type, name, tbl_name, sql`,
    ),
  );
  const tableNames = classifiedManifestStep("D1TablePolicyError", () => {
    const names = schemaRows
      .filter((row) => row.type === "table" && isApplicationSchemaRow(row))
      .map(({ name }) => name)
      .sort();
    assert.ok(names.length > 0, "application schema contains no tables");
    for (const table of names) assert.match(table, APPLICATION_TABLE_PATTERN);
    return names;
  });
  const rowCounts = classifiedManifestStep("D1RowCountError", () => {
    return Object.fromEntries(
      tableNames.map((table, index) => [
        table,
        classifiedManifestStep(
          `D1RowCountTable${String(index).padStart(2, "0")}Error`,
          () =>
            normalizeSingleRowCount(
              queryRows(
                projectDirectory,
                trustedTableCountSql(table),
              ),
            ),
        ),
      ]),
    );
  });
  const integrity = classifiedManifestStep("D1IntegrityError", () =>
    queryRows(projectDirectory, D1_CONSISTENCY_CHECK_SQL),
  );
  const foreignKeys = classifiedManifestStep("D1ForeignKeyError", () =>
    queryRows(projectDirectory, "PRAGMA foreign_key_check"),
  );
  const migrationLedger = classifiedManifestStep(
    "D1MigrationLedgerError",
    () =>
      normalizeMigrationLedgerRows(
        queryRows(
          projectDirectory,
          "SELECT id, name FROM d1_migrations ORDER BY id",
        ),
      ),
  );
  const schemaSha256 = classifiedManifestStep("D1SchemaHashError", () =>
    schemaHash(schemaRows.filter(isApplicationSchemaRow)),
  );
  return {
    migrationLedger,
    rowCounts,
    schemaSha256,
    integrityOk: quickCheckPassed(integrity),
    foreignKeysOk: foreignKeys.length === 0,
  };
}

export function readContinuityRecords(projectDirectory) {
  const exactRecord = (sql, label) => {
    const rows = queryRows(projectDirectory, sql);
    assert.equal(rows.length, 1, `${label} fixture is missing`);
    return rows[0];
  };
  return {
    user_record: exactRecord(
      `SELECT id, emailVerified, role, status, accessLevel
         FROM user
        WHERE id = '10000000-0000-4000-8000-000000000001'`,
      "user",
    ),
    passkey_record: exactRecord(
      `SELECT id, userId, credentialID, publicKey, counter, deviceType, backedUp
         FROM passkey
        WHERE id = '20000000-0000-4000-8000-000000000001'`,
      "passkey",
    ),
    client_record: exactRecord(
      `SELECT id, clientId, clientSecret, redirectUris, postLogoutRedirectUris,
              backchannelLogoutUri, tokenEndpointAuthMethod, grantTypes,
              responseTypes, scopes, requirePKCE, skipConsent, ownerUserId
         FROM oauthClient
        WHERE clientId = 'continuity-rp'`,
      "client",
    ),
    consent_record: exactRecord(
      `SELECT id, clientId, userId, referenceId, scopes
         FROM oauthConsent
        WHERE id = '40000000-0000-4000-8000-000000000001'`,
      "consent",
    ),
    session_records: queryRows(
      projectDirectory,
      `SELECT id, userId, expiresAt
         FROM session
        WHERE userId = '10000000-0000-4000-8000-000000000001'
        ORDER BY id`,
    ),
    jwks_records: queryRows(
      projectDirectory,
      `SELECT id, publicKey, privateKey, createdAt, expiresAt
         FROM jwks
        ORDER BY id`,
    ),
    visit_records: queryRows(
      projectDirectory,
      `SELECT session_id, client_id
         FROM rp_session_client
        ORDER BY session_id, client_id`,
    ),
  };
}

export function assertEquivalentD1(source, restored, sourceRecords, restoredRecords) {
  assert.deepEqual(restored, source, "restored D1 manifest differs from source");
  assert.deepEqual(
    restoredRecords,
    sourceRecords,
    "restored synthetic records differ from source",
  );
}
