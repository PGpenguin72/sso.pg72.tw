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
import { assertEquivalentD1 } from "./d1-manifest.mjs";
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
