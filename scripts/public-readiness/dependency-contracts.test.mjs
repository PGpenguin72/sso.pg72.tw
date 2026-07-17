import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  REQUIRED_DEPENDENCY_NAMES,
  dependencyStatus,
  runGlobalLogoutDependencyProof,
  validateGlobalLogoutProofReport,
} from "./dependency-contracts.mjs";
import { ssoRoot } from "./local-runtime.mjs";
import { readinessFromDependencies } from "./report.mjs";

function writeFixture(filename, value) {
  mkdirSync(path.dirname(filename), { recursive: true });
  writeFileSync(filename, value);
}

function createDependencyFixture() {
  const repositoryRoot = mkdtempSync(
    path.join(os.tmpdir(), "pgid-readiness-dependencies-"),
  );
  const identityRoot = path.join(repositoryRoot, "apps", "sso");
  writeFixture(
    path.join(identityRoot, "migrations", "0018_global_logout.sql"),
    `ALTER TABLE "logout_delivery" RENAME TO "logout_delivery_legacy_0018";
     CREATE TABLE "rp_session_client" (id text);
     CREATE TABLE "logout_delivery" (id text);
     CREATE TABLE "logout_delivery_attempt" (id text);
     CREATE TRIGGER "oauth_access_token_record_rp_visit"
       AFTER INSERT ON "logout_delivery" BEGIN SELECT 1; END;`,
  );
  writeFixture(
    path.join(identityRoot, "migrations", "0019_recovery_codes.sql"),
    `CREATE TABLE "recovery_code_set" (id text);
     CREATE TABLE "recovery_code" (id text);
     CREATE TABLE "recovery_session" (id text);
     CREATE TABLE "recovery_passkey_challenge" (id text);
     CREATE UNIQUE INDEX "passkey_credential_id_unique_idx"
       ON "recovery_code" (id);
     CREATE TRIGGER "user_recovery_session_suspension_cleanup"
       AFTER INSERT ON "recovery_code" BEGIN SELECT 1; END;`,
  );
  writeFixture(
    path.join(identityRoot, "migrations", "0020_alert_observability.sql"),
    `CREATE TABLE "alert_state" (id text);
     CREATE TABLE "alert_outbox" (id text);
     CREATE INDEX "alert_outbox_due_idx" ON "alert_outbox" (id);`,
  );
  writeFixture(
    path.join(identityRoot, "worker", "audit-archive.ts"),
    `export const PUBLIC_READINESS_ARCHIVE_CONTRACT = "pgid-audit-archive-v1";
     export async function archiveAuditBatch() { return true; }
     export async function restoreAuditArchive() { return true; }`,
  );
  writeFixture(
    path.join(identityRoot, "wrangler.jsonc"),
    `{
      // This must be parsed as JSONC rather than matched as text.
      "r2_buckets": [
        { "binding": "AUDIT_ARCHIVE", "bucket_name": "pgid-audit-archive" }
      ]
    }`,
  );
  writeFixture(
    path.join(repositoryRoot, "security", "release-policy.json"),
    `${JSON.stringify({
      schemaVersion: 2,
      artifact: { entrypoint: "index.js" },
      staticAssets: { entrypoint: "index.html" },
      environments: {
        production: {
          sourceConfig: "apps/sso/wrangler.jsonc",
          worker: { name: "pg72-id" },
        },
        localTestRp: { sourceConfig: "apps/test-rp/wrangler.jsonc" },
      },
    })}\n`,
  );
  writeFixture(
    path.join(repositoryRoot, "scripts", "security", "dast.mjs"),
    `export function authorizeDastTarget() { return true; }
     export async function scanPgid() { return []; }
     export async function scanLocalRp() { return []; }`,
  );
  return { identityRoot, repositoryRoot };
}

function statusOf(entries, name) {
  return entries.find((entry) => entry.name === name)?.status;
}

function globalLogoutProofReport(overrides = {}) {
  return {
    numFailedTestSuites: 0,
    numFailedTests: 0,
    numPassedTestSuites: 2,
    numPassedTests: 25,
    numPendingTestSuites: 0,
    numPendingTests: 0,
    numTodoTests: 0,
    numTotalTestSuites: 2,
    numTotalTests: 25,
    success: true,
    testResults: [
      {
        assertionResults: Array.from({ length: 25 }, () => ({
          ancestorTitles: ["durable global logout"],
          status: "passed",
        })),
        name: path.join(ssoRoot, "test", "global-logout.spec.ts"),
        status: "passed",
      },
    ],
    ...overrides,
  };
}

test("valid source remains unverified and caller assertions cannot promote it", () => {
  const fixture = createDependencyFixture();
  try {
    const dependencies = dependencyStatus(fixture);
    assert.ok(
      dependencies.every(({ status }) => status === "source_present_unverified"),
    );
    assert.deepEqual(readinessFromDependencies(dependencies), {
      ready: false,
      status: "blocked",
    });
    assert.throws(
      () =>
        dependencyStatus({
          ...fixture,
          verified: REQUIRED_DEPENDENCY_NAMES,
        }),
      /unapproved option/,
    );
    assert.throws(
      () => dependencyStatus({ ...fixture, proofs: [{}] }),
      /not produced by an executed check/,
    );
  } finally {
    rmSync(fixture.repositoryRoot, { force: true, recursive: true });
  }
});

test("only the executed repo-bound global-logout check produces its proof", () => {
  const homeDirectory = mkdtempSync(
    path.join(os.tmpdir(), "pgid-global-logout-proof-"),
  );
  try {
    const proof = runGlobalLogoutDependencyProof(homeDirectory);
    const dependencies = dependencyStatus({ proofs: [proof] });
    assert.equal(
      statusOf(dependencies, "global_logout_0018"),
      "verified",
    );
    assert.ok(
      dependencies
        .filter(({ name }) => name !== "global_logout_0018")
        .every(({ status }) => status !== "verified"),
    );
    assert.throws(
      () => dependencyStatus({ proofs: [proof, proof] }),
      /duplicated/,
    );
  } finally {
    rmSync(homeDirectory, { force: true, recursive: true });
  }
});

test("global-logout proof rejects skipped, partial, wrong-file, and malformed results", () => {
  assert.doesNotThrow(() =>
    validateGlobalLogoutProofReport(globalLogoutProofReport()),
  );
  assert.throws(() =>
    validateGlobalLogoutProofReport(
      globalLogoutProofReport({
        numPassedTestSuites: 0,
        numPassedTests: 0,
        numPendingTestSuites: 2,
        numPendingTests: 25,
        testResults: [
          {
            assertionResults: Array.from({ length: 25 }, () => ({
              ancestorTitles: ["durable global logout"],
              status: "pending",
            })),
            name: path.join(ssoRoot, "test", "global-logout.spec.ts"),
            status: "pending",
          },
        ],
      }),
    ),
  );
  assert.throws(() =>
    validateGlobalLogoutProofReport(
      globalLogoutProofReport({
        numPassedTests: 24,
        numPendingTests: 1,
      }),
    ),
  );
  for (const mutation of [
    { numFailedTests: 1 },
    { numFailedTestSuites: 1 },
    { numTodoTests: 1 },
  ]) {
    assert.throws(() =>
      validateGlobalLogoutProofReport(globalLogoutProofReport(mutation)),
    );
  }
  for (const ancestorTitles of [[], ["lookalike suite"]]) {
    const report = globalLogoutProofReport();
    report.testResults[0].assertionResults[0].ancestorTitles = ancestorTitles;
    assert.throws(() => validateGlobalLogoutProofReport(report));
  }
  assert.throws(() =>
    validateGlobalLogoutProofReport(
      globalLogoutProofReport({
        testResults: [
          {
            assertionResults: Array.from({ length: 25 }, () => ({
              ancestorTitles: ["durable global logout"],
              status: "passed",
            })),
            name: path.join(ssoRoot, "test", "lookalike.spec.ts"),
            status: "passed",
          },
        ],
      }),
    ),
  );
  assert.throws(() => validateGlobalLogoutProofReport({ success: true }));
});

test("empty dependency sources remain invalid", () => {
  const targets = new Map([
    ["global_logout_0018", ["apps", "sso", "migrations", "0018_global_logout.sql"]],
    ["recovery_0019", ["apps", "sso", "migrations", "0019_recovery_codes.sql"]],
    ["observability_0020", ["apps", "sso", "migrations", "0020_alert_observability.sql"]],
    ["encrypted_r2_archive", ["apps", "sso", "worker", "audit-archive.ts"]],
    ["release_automation", ["security", "release-policy.json"]],
  ]);
  for (const [name, segments] of targets) {
    const fixture = createDependencyFixture();
    try {
      writeFileSync(path.join(fixture.repositoryRoot, ...segments), "");
      const dependencies = dependencyStatus(fixture);
      assert.equal(statusOf(dependencies, name), "source_invalid", name);
      assert.equal(readinessFromDependencies(dependencies).ready, false);
    } finally {
      rmSync(fixture.repositoryRoot, { force: true, recursive: true });
    }
  }
});

test("truncated and wrong dependency contracts cannot become verified", () => {
  const mutations = new Map([
    [
      "global_logout_0018",
      [
        "apps",
        "sso",
        "migrations",
        "0018_global_logout.sql",
        'CREATE TABLE "logout_delivery" (id text);',
      ],
    ],
    [
      "recovery_0019",
      [
        "apps",
        "sso",
        "migrations",
        "0019_recovery_codes.sql",
        'CREATE TABLE "recovery_code" (id text);',
      ],
    ],
    [
      "observability_0020",
      [
        "apps",
        "sso",
        "migrations",
        "0020_alert_observability.sql",
        'CREATE TABLE "alert_state" (id text);',
      ],
    ],
    [
      "encrypted_r2_archive",
      [
        "apps",
        "sso",
        "worker",
        "audit-archive.ts",
        'export const PUBLIC_READINESS_ARCHIVE_CONTRACT = "lookalike";',
      ],
    ],
    [
      "release_automation",
      [
        "security",
        "release-policy.json",
        '{"schemaVersion":2,"artifact":{"entrypoint":"index.js"}}',
      ],
    ],
  ]);
  for (const [name, mutation] of mutations) {
    const fixture = createDependencyFixture();
    try {
      writeFileSync(
        path.join(fixture.repositoryRoot, ...mutation.slice(0, -1)),
        mutation.at(-1),
      );
      const dependencies = dependencyStatus(fixture);
      assert.equal(statusOf(dependencies, name), "source_invalid", name);
    } finally {
      rmSync(fixture.repositoryRoot, { force: true, recursive: true });
    }
  }
});

test("lookalike filenames do not satisfy exact dependency paths", () => {
  const paths = [
    ["apps", "sso", "migrations", "0018_global_logout.sql"],
    ["apps", "sso", "migrations", "0019_recovery_codes.sql"],
    ["apps", "sso", "migrations", "0020_alert_observability.sql"],
    ["apps", "sso", "worker", "audit-archive.ts"],
    ["security", "release-policy.json"],
  ];
  for (const segments of paths) {
    const fixture = createDependencyFixture();
    try {
      const exact = path.join(fixture.repositoryRoot, ...segments);
      renameSync(exact, `${exact}.lookalike`);
      assert.ok(
        dependencyStatus(fixture).some(
          ({ status }) => status === "dependency_missing",
        ),
      );
    } finally {
      rmSync(fixture.repositoryRoot, { force: true, recursive: true });
    }
  }
});

test("commented and remote R2 config lookalikes are source-invalid", () => {
  for (const config of [
    '{ // "r2_buckets": [{"binding":"AUDIT_ARCHIVE","bucket_name":"lookalike"}]\n}',
    '{"r2_buckets":[{"binding":"AUDIT_ARCHIVE","bucket_name":"lookalike","remote":true}]}',
  ]) {
    const fixture = createDependencyFixture();
    try {
      writeFileSync(path.join(fixture.identityRoot, "wrangler.jsonc"), config);
      assert.equal(
        statusOf(dependencyStatus(fixture), "encrypted_r2_archive"),
        "source_invalid",
      );
    } finally {
      rmSync(fixture.repositoryRoot, { force: true, recursive: true });
    }
  }
});

test("SQL contract markers inside comments cannot satisfy source evidence", () => {
  for (const [name, filename] of [
    ["global_logout_0018", "0018_global_logout.sql"],
    ["recovery_0019", "0019_recovery_codes.sql"],
    ["observability_0020", "0020_alert_observability.sql"],
  ]) {
    const fixture = createDependencyFixture();
    try {
      const target = path.join(fixture.identityRoot, "migrations", filename);
      const original = readFileSync(target, "utf8");
      writeFileSync(target, `-- ${original.replaceAll("\n", "\n-- ")}\n`);
      assert.equal(statusOf(dependencyStatus(fixture), name), "source_invalid");
    } finally {
      rmSync(fixture.repositoryRoot, { force: true, recursive: true });
    }
  }
});
