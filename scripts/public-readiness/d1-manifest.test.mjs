import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
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
  assertEquivalentD1,
  classifiedManifestStep,
  expectedMigrationHead,
  isApplicationSchemaRow,
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
    migrationHead: "0018_global_logout.sql",
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

test("derives the migration head from the integrated source sequence", () => {
  const migrationsDirectory = path.join(ssoRoot, "migrations");
  const expected = readdirSync(migrationsDirectory)
    .filter((name) => /^\d{4}_[a-z0-9_]+\.sql$/.test(name))
    .sort()
    .at(-1);
  assert.equal(expectedMigrationHead(migrationsDirectory), expected);
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
