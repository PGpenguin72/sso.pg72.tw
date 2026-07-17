import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

import { runWrangler } from "./local-runtime.mjs";

const APPLICATION_TABLE_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

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
  const schemaRows = queryRows(
    projectDirectory,
    `SELECT type, name, tbl_name, sql
       FROM sqlite_schema
      WHERE sql IS NOT NULL
      ORDER BY type, name, tbl_name, sql`,
  );
  const tableNames = schemaRows
    .filter(({ type, name }) => type === "table" && !name.startsWith("sqlite_") && name !== "d1_migrations")
    .map(({ name }) => name)
    .sort();
  for (const table of tableNames) assert.match(table, APPLICATION_TABLE_PATTERN);
  const countSql = tableNames
    .map(
      (table) =>
        `SELECT '${table}' AS table_name, COUNT(*) AS row_count FROM "${table}"`,
    )
    .join(" UNION ALL ");
  const rowCounts = Object.fromEntries(
    queryRows(projectDirectory, countSql).map(({ row_count, table_name }) => [
      table_name,
      Number(row_count),
    ]),
  );
  const integrity = queryRows(projectDirectory, "PRAGMA integrity_check");
  const foreignKeys = queryRows(projectDirectory, "PRAGMA foreign_key_check");
  const migration = queryRows(
    projectDirectory,
    "SELECT name FROM d1_migrations ORDER BY id DESC LIMIT 1",
  )[0];
  return {
    migrationHead: migration?.name ?? null,
    rowCounts,
    schemaSha256: schemaHash(schemaRows),
    integrityOk:
      integrity.length === 1 && Object.values(integrity[0]).includes("ok"),
    foreignKeysOk: foreignKeys.length === 0,
  };
}

export function readContinuityRecords(projectDirectory) {
  const rows = queryRows(
    projectDirectory,
    `SELECT
      (SELECT json_object(
        'id', id, 'emailVerified', emailVerified, 'role', role,
        'status', status, 'accessLevel', accessLevel
       ) FROM user WHERE id = '10000000-0000-4000-8000-000000000001') AS user_record,
      (SELECT json_object(
        'id', id, 'userId', userId, 'credentialID', credentialID,
        'publicKey', publicKey, 'counter', counter, 'deviceType', deviceType,
        'backedUp', backedUp
       ) FROM passkey WHERE id = '20000000-0000-4000-8000-000000000001') AS passkey_record,
      (SELECT json_object(
        'id', id, 'clientId', clientId, 'clientSecret', clientSecret,
        'redirectUris', redirectUris,
        'postLogoutRedirectUris', postLogoutRedirectUris,
        'backchannelLogoutUri', backchannelLogoutUri,
        'tokenEndpointAuthMethod', tokenEndpointAuthMethod,
        'grantTypes', grantTypes, 'responseTypes', responseTypes,
        'scopes', scopes, 'requirePKCE', requirePKCE,
        'skipConsent', skipConsent, 'ownerUserId', ownerUserId
       ) FROM oauthClient WHERE clientId = 'continuity-rp') AS client_record,
      (SELECT json_object(
        'id', id, 'clientId', clientId, 'userId', userId,
        'referenceId', referenceId, 'scopes', scopes
       ) FROM oauthConsent WHERE id = '40000000-0000-4000-8000-000000000001') AS consent_record,
      (SELECT json_group_array(json_object(
        'id', id, 'userId', userId, 'expiresAt', expiresAt
       )) FROM (SELECT id, userId, expiresAt FROM session
        WHERE userId = '10000000-0000-4000-8000-000000000001' ORDER BY id)) AS session_records,
      (SELECT json_group_array(json_object(
        'id', id, 'publicKey', publicKey, 'privateKey', privateKey,
        'createdAt', createdAt, 'expiresAt', expiresAt
       )) FROM (SELECT id, publicKey, privateKey, createdAt, expiresAt
        FROM jwks ORDER BY id)) AS jwks_records,
      (SELECT json_group_array(json_object(
        'session_id', session_id, 'client_id', client_id
       )) FROM (SELECT session_id, client_id FROM rp_session_client
        ORDER BY session_id, client_id)) AS visit_records`,
  );
  assert.equal(rows.length, 1, "continuity fixture query returned the wrong row count");
  const row = rows[0];
  return Object.fromEntries(
    Object.entries(row).map(([name, value]) => {
      assert.equal(typeof value, "string", `${name} fixture is missing`);
      return [name, JSON.parse(value)];
    }),
  );
}

export function assertEquivalentD1(source, restored, sourceRecords, restoredRecords) {
  assert.deepEqual(restored, source, "restored D1 manifest differs from source");
  assert.deepEqual(
    restoredRecords,
    sourceRecords,
    "restored synthetic records differ from source",
  );
}
