import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  REQUIRED_DEPENDENCY_NAMES,
  dependencyStatus,
  exactFileSetFingerprint,
  runGlobalLogoutDependencyProof,
  runRecoveryDependencyProof,
  runReleaseAutomationDependencyProof,
  validateGlobalLogoutProofReport,
  validateRecoveryProofReport,
  validateReleaseAutomationProofEvents,
} from "./dependency-contracts.mjs";
import { repoRoot, ssoRoot } from "./local-runtime.mjs";
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
    `ALTER TABLE "audit_event" ADD COLUMN "actor_ref" text;
     ALTER TABLE "audit_event" ADD COLUMN "actor_ref_hash_version" integer;
     ALTER TABLE "oauth_client_report" ADD COLUMN "reporter_ref" text;
     ALTER TABLE "oauth_client_report"
       ADD COLUMN "reporter_ref_hash_version" integer;
     CREATE TABLE "alert_hash_key_sentinel" (id integer);
     CREATE TRIGGER "alert_hash_key_sentinel_insert_guard"
       BEFORE INSERT ON "alert_hash_key_sentinel" BEGIN SELECT 1; END;
     CREATE TRIGGER "audit_event_actor_identity_update_guard"
       AFTER UPDATE ON "alert_hash_key_sentinel" BEGIN SELECT 1; END;
     CREATE TRIGGER "oauth_client_report_identity_update_guard"
       AFTER UPDATE ON "alert_hash_key_sentinel" BEGIN SELECT 1; END;
     CREATE INDEX "audit_event_invalid_occurred_at_idx"
       ON "alert_hash_key_sentinel" (id);
     CREATE TRIGGER "audit_event_occurred_at_insert_guard"
       BEFORE INSERT ON "alert_hash_key_sentinel" BEGIN SELECT 1; END;
     CREATE TRIGGER "audit_event_occurred_at_update_guard"
       BEFORE UPDATE ON "alert_hash_key_sentinel" BEGIN SELECT 1; END;
     CREATE INDEX "oauth_client_report_invalid_created_at_idx"
       ON "alert_hash_key_sentinel" (id);
     CREATE TRIGGER "oauth_client_report_created_at_insert_guard"
       BEFORE INSERT ON "alert_hash_key_sentinel" BEGIN SELECT 1; END;
     CREATE TRIGGER "oauth_client_report_created_at_update_guard"
       BEFORE UPDATE ON "alert_hash_key_sentinel" BEGIN SELECT 1; END;
     CREATE TABLE "alert_state" (
       id text,
       "minimum_numerator_count" integer,
       "last_notification_scheduled_at" date
     );
     CREATE TABLE "security_alert" (id text);
     CREATE TABLE "alert_outbox" (id text);
     CREATE TABLE "alert_delivery_attempt" (id text);
     CREATE TABLE "alert_runtime_status" (
       id text,
       "consecutive_nonzero_samples" integer
     );
     CREATE TABLE "alert_evaluator_bootstrap" (
       "component" text,
       "first_success_at" date,
       "source_generation" integer,
       "source_revision" integer,
       FOREIGN KEY ("component") REFERENCES "alert_runtime_status" ("component")
         ON DELETE RESTRICT
     );
     CREATE UNIQUE INDEX "alert_state_semantic_identity_idx"
       ON "alert_state" (id);
     CREATE UNIQUE INDEX "security_alert_unresolved_state_idx"
       ON "security_alert" (id);
     CREATE INDEX "alert_outbox_due_idx" ON "alert_outbox" (id);
     CREATE TRIGGER "alert_state_initial_guard"
       AFTER INSERT ON "alert_state" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_state_transition_guard"
       AFTER UPDATE ON "alert_state" BEGIN SELECT 1; END;
     CREATE TRIGGER "security_alert_insert_state_guard"
       AFTER INSERT ON "security_alert" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_outbox_reminder_sequence_guard"
       BEFORE INSERT ON "alert_outbox" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_delivery_attempt_insert_guard"
       AFTER INSERT ON "alert_delivery_attempt" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_delivery_attempt_transition_guard"
       AFTER UPDATE ON "alert_delivery_attempt" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_runtime_status_transition_guard"
       AFTER UPDATE ON "alert_runtime_status" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_evaluator_bootstrap_insert_guard"
       BEFORE INSERT ON "alert_evaluator_bootstrap" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_evaluator_bootstrap_update_guard"
       BEFORE UPDATE ON "alert_evaluator_bootstrap" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_evaluator_bootstrap_delete_guard"
       BEFORE DELETE ON "alert_evaluator_bootstrap" BEGIN SELECT 1; END;
     CREATE INDEX "audit_event_type_subject_time_bounded_idx"
       ON "alert_state" (id);
     CREATE INDEX "audit_event_time_bounded_idx" ON "alert_state" (id);
     CREATE INDEX "audit_event_type_actor_time_bounded_idx"
       ON "alert_state" (id);
     CREATE INDEX "audit_event_type_time_bounded_idx" ON "alert_state" (id);
     CREATE INDEX "oauth_client_report_time_client_reason_reporter_bounded_idx"
       ON "alert_state" (id);
     CREATE INDEX "logout_delivery_time_client_status_bounded_idx"
       ON "alert_state" (id);
     CREATE INDEX "logout_delivery_status_client_time_bounded_idx"
       ON "alert_state" (id);
     CREATE INDEX "logout_delivery_attempt_completion_bounded_idx"
       ON "alert_state" (id);`,
  );
  writeFixture(
    path.join(identityRoot, "migrations", "0021_audit_archive.sql"),
    `CREATE TABLE "audit_archive_source" (id integer);
     CREATE TABLE "audit_archive_key_sentinel" (id integer);
     CREATE TABLE "audit_archive_checkpoint" (id integer);
     CREATE TABLE "audit_archive_batch" (id integer);
     CREATE TABLE "audit_archive_batch_item" (id integer);
     CREATE TABLE "audit_archive_attempt" (id integer);
     CREATE TRIGGER "audit_archive_source_parent_time_guard"
       BEFORE INSERT ON "audit_archive_source" BEGIN SELECT 1; END;
     CREATE TRIGGER "audit_archive_source_insert_guard"
       BEFORE INSERT ON "audit_archive_source" BEGIN SELECT 1; END;
     CREATE TRIGGER "audit_event_archive_identity_insert_guard"
       BEFORE INSERT ON "audit_archive_source" BEGIN SELECT 1; END;
     CREATE TRIGGER "audit_archive_batch_item_insert_guard"
       BEFORE INSERT ON "audit_archive_batch_item" BEGIN SELECT 1; END;
     CREATE TRIGGER "audit_archive_attempt_apply_terminal"
       AFTER UPDATE ON "audit_archive_attempt" BEGIN SELECT 1; END;
     CREATE TRIGGER "audit_archive_batch_advance_checkpoint"
       AFTER UPDATE ON "audit_archive_batch" BEGIN SELECT 1; END;`,
  );
  writeFixture(
    path.join(
      identityRoot,
      "migrations",
      "0022_alert_evaluator_run_proof.sql",
    ),
    `CREATE TABLE "alert_evaluator_run" (
       trigger_cron text,
       trigger_scheduled_at text,
       UNIQUE ("trigger_cron", "trigger_scheduled_at")
     );
     CREATE TABLE "alert_evaluator_run_source" (
       run_id text,
       source_id text,
       PRIMARY KEY (run_id, source_id)
     );
     CREATE TABLE "alert_evaluator_run_decision" (
       run_id text,
       source_id text,
       FOREIGN KEY ("run_id", "source_id")
         REFERENCES "alert_evaluator_run_source" (run_id, source_id)
     );
     CREATE TRIGGER "alert_evaluator_run_acquire_runtime"
       AFTER INSERT ON "alert_evaluator_run" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_runtime_evaluator_lease_run_guard"
       AFTER INSERT ON "alert_evaluator_run" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_runtime_evaluator_idle_update_guard"
       AFTER INSERT ON "alert_evaluator_run" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_evaluator_run_renew_runtime"
       AFTER INSERT ON "alert_evaluator_run" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_runtime_evaluator_terminal_run_guard"
       AFTER INSERT ON "alert_evaluator_run" BEGIN SELECT 1; END;
     CREATE TRIGGER "alert_runtime_evaluator_terminalize_run"
       AFTER INSERT ON "alert_evaluator_run" BEGIN SELECT 1; END;
     CREATE INDEX "alert_evaluator_run_status_expiry_idx"
       ON "alert_evaluator_run" (trigger_scheduled_at);`,
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

function assertTrackedExecutionMutationRejected(proof, relative) {
  const filename = path.join(repoRoot, relative);
  const original = readFileSync(filename);
  try {
    writeFileSync(
      filename,
      Buffer.concat([original, Buffer.from("\n// proof-drift-regression\n")]),
    );
    assert.throws(
      () => dependencyStatus({ proofs: [proof] }),
      /source no longer matches its executed proof/,
    );
  } finally {
    writeFileSync(filename, original);
  }
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

function recoveryProofReport(overrides = {}) {
  const groups = [
    ["recovery code management", 7],
    ["restricted recovery entry", 9],
    ["recovery Passkey completion", 4],
  ];
  return {
    numFailedTestSuites: 0,
    numFailedTests: 0,
    numPassedTestSuites: 4,
    numPassedTests: 20,
    numPendingTestSuites: 0,
    numPendingTests: 0,
    numTodoTests: 0,
    numTotalTestSuites: 4,
    numTotalTests: 20,
    success: true,
    testResults: [
      {
        assertionResults: groups.flatMap(([ancestor, count]) =>
          Array.from({ length: count }, () => ({
            ancestorTitles: [ancestor],
            status: "passed",
          })),
        ),
        name: path.join(ssoRoot, "test", "recovery.spec.ts"),
        status: "passed",
      },
    ],
    ...overrides,
  };
}

const releaseTestCounts = new Map([
  ["accepted-advisories.test.mjs", 5],
  ["artifact-gate.test.mjs", 11],
  ["dast.test.mjs", 6],
  ["dependency-inventory.test.mjs", 2],
  ["release-identity.test.mjs", 13],
  ["secret-family.test.mjs", 20],
  ["secret-scan.test.mjs", 2],
  ["workflow-config.test.mjs", 25],
  ["wrangler-config.test.mjs", 5],
]);

function nodeTestCounts(count) {
  return {
    tests: count,
    failed: 0,
    passed: count,
    cancelled: 0,
    skipped: 0,
    todo: 0,
    topLevel: count,
    suites: 0,
  };
}

function releaseProofEvents() {
  const events = [];
  let testNumber = 0;
  for (const [filename, count] of releaseTestCounts) {
    const file = path.join(repoRoot, "scripts", "security", filename);
    for (let index = 0; index < count; index += 1) {
      testNumber += 1;
      events.push({
        type: "test:pass",
        data: {
          name: `${filename}:${index}`,
          nesting: 0,
          testNumber,
          details: { type: "test" },
          file,
        },
      });
    }
    events.push({
      type: "test:summary",
      data: { success: true, counts: nodeTestCounts(count), file },
    });
  }
  events.push({
    type: "test:summary",
    data: { success: true, counts: nodeTestCounts(testNumber) },
  });
  return events;
}

function eventSource(events) {
  return `${events.map((event) => JSON.stringify(event)).join("\n")}\n`;
}

test("exact file-set fingerprints reject path escapes and non-regular nodes", (context) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "pgid-exact-fingerprint-"));
  const rootLink = `${root}-link`;
  context.after(() => rmSync(root, { force: true, recursive: true }));
  context.after(() => rmSync(rootLink, { force: true }));
  writeFixture(path.join(root, "a.txt"), "alpha");
  writeFixture(path.join(root, "nested", "b.txt"), "bravo");

  const files = ["a.txt", "nested/b.txt"];
  const baseline = exactFileSetFingerprint(root, files);
  assert.match(baseline, /^[a-f0-9]{64}$/);
  assert.equal(exactFileSetFingerprint(root, files), baseline);
  writeFileSync(path.join(root, "nested", "b.txt"), "changed");
  assert.notEqual(exactFileSetFingerprint(root, files), baseline);

  assert.throws(
    () => exactFileSetFingerprint(root, [path.join(root, "a.txt")]),
    /must be relative/,
  );
  assert.throws(
    () => exactFileSetFingerprint(root, ["C:\\outside.txt"]),
    /absolute Windows path/,
  );
  assert.throws(
    () => exactFileSetFingerprint(root, ["../outside.txt"]),
    /escaped its repository root/,
  );
  assert.throws(
    () => exactFileSetFingerprint(root, []),
    /must not be empty/,
  );
  assert.throws(
    () => exactFileSetFingerprint(root, ["nested/b.txt", "a.txt"]),
    /exact, unique, and ordered/,
  );
  assert.throws(
    () => exactFileSetFingerprint(root, ["a.txt", "a.txt"]),
    /exact, unique, and ordered/,
  );

  symlinkSync("a.txt", path.join(root, "leaf-link.txt"));
  assert.throws(
    () => exactFileSetFingerprint(root, ["leaf-link.txt"]),
    /not an exact regular file/,
  );
  symlinkSync("nested", path.join(root, "linked-nested"), "dir");
  assert.throws(
    () => exactFileSetFingerprint(root, ["linked-nested/b.txt"]),
    /symbolic-link ancestor/,
  );
  symlinkSync(root, rootLink, "dir");
  assert.throws(
    () => exactFileSetFingerprint(rootLink, ["a.txt"]),
    /root must be an exact directory/,
  );
  mkdirSync(path.join(root, "directory-entry"));
  assert.throws(
    () => exactFileSetFingerprint(root, ["directory-entry"]),
    /not an exact regular file/,
  );
});

test("valid source remains unverified and caller assertions cannot promote it", () => {
  const fixture = createDependencyFixture();
  try {
    const dependencies = dependencyStatus(fixture);
    assert.ok(
      dependencies.every(({ status }) => status === "source_present_unverified"),
    );
    assert.equal(
      statusOf(dependencies, "observability_0020"),
      "source_present_unverified",
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
    assertTrackedExecutionMutationRejected(
      proof,
      "apps/sso/worker/global-logout.ts",
    );
    assert.equal(
      statusOf(dependencyStatus({ proofs: [proof] }), "global_logout_0018"),
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

test("only same-run recovery and release checks produce their opaque proofs", () => {
  const homeDirectory = mkdtempSync(
    path.join(os.tmpdir(), "pgid-integrated-dependency-proofs-"),
  );
  try {
    const recoveryProof = runRecoveryDependencyProof(homeDirectory);
    assertTrackedExecutionMutationRejected(
      recoveryProof,
      "apps/sso/worker/recovery.ts",
    );
    const releaseProof = runReleaseAutomationDependencyProof(homeDirectory);
    for (const relative of [
      "scripts/security/secret-family.mjs",
      "scripts/security/secret-family.test.mjs",
      "scripts/security/typescript-static-values.mjs",
    ]) {
      assertTrackedExecutionMutationRejected(releaseProof, relative);
    }
    const dependencies = dependencyStatus({
      proofs: [recoveryProof, releaseProof],
    });
    assert.equal(statusOf(dependencies, "recovery_0019"), "verified");
    assert.equal(statusOf(dependencies, "release_automation"), "verified");
    assert.equal(
      statusOf(dependencies, "observability_0020"),
      "source_present_unverified",
    );
    assert.ok(
      dependencies
        .filter(({ name }) => !["recovery_0019", "release_automation"].includes(name))
        .every(({ status }) => status !== "verified"),
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

test("recovery proof rejects failed, partial, skipped, wrong-file, and wrong-suite results", () => {
  assert.doesNotThrow(() => validateRecoveryProofReport(recoveryProofReport()));
  for (const mutation of [
    { success: false },
    { numPassedTestSuites: 3 },
    { numTotalTestSuites: 3 },
    { numPassedTests: 19 },
    { numTotalTests: 19 },
    { numPendingTests: 1 },
    { numPendingTestSuites: 1 },
    { numFailedTests: 1 },
    { numFailedTestSuites: 1 },
    { numTodoTests: 1 },
  ]) {
    assert.throws(() =>
      validateRecoveryProofReport(recoveryProofReport(mutation)),
    );
  }

  const wrongFile = recoveryProofReport();
  wrongFile.testResults[0].name = path.join(ssoRoot, "test", "lookalike.spec.ts");
  assert.throws(() => validateRecoveryProofReport(wrongFile));

  const wrongStatus = recoveryProofReport();
  wrongStatus.testResults[0].status = "pending";
  assert.throws(() => validateRecoveryProofReport(wrongStatus));

  const wrongAncestorCount = recoveryProofReport();
  wrongAncestorCount.testResults[0].assertionResults[0].ancestorTitles = [
    "restricted recovery entry",
  ];
  assert.throws(() => validateRecoveryProofReport(wrongAncestorCount));

  const wrongAncestor = recoveryProofReport();
  wrongAncestor.testResults[0].assertionResults[0].ancestorTitles = [
    "lookalike recovery suite",
  ];
  assert.throws(() => validateRecoveryProofReport(wrongAncestor));

  const partialAssertions = recoveryProofReport();
  partialAssertions.testResults[0].assertionResults.pop();
  assert.throws(() => validateRecoveryProofReport(partialAssertions));
});

test("release proof rejects malformed, failed, missing, duplicate, and skipped events", () => {
  const baseline = releaseProofEvents();
  assert.doesNotThrow(() =>
    validateReleaseAutomationProofEvents(eventSource(baseline)),
  );
  assert.throws(() => validateReleaseAutomationProofEvents("{not-json}\n"));

  const mutations = [
    (events) => events.push({ type: "test:diagnostic", data: {} }),
    (events) => events.push({ type: "test:fail", data: {} }),
    (events) => events.splice(events.findIndex(({ type }) => type === "test:pass"), 1),
    (events) => events.push(structuredClone(events.find(({ type }) => type === "test:pass"))),
    (events) => {
      events.find(({ type }) => type === "test:pass").data.file = path.join(
        repoRoot,
        "scripts",
        "security",
        "lookalike.test.mjs",
      );
    },
    (events) => events.splice(events.findIndex(({ type, data }) => type === "test:summary" && data.file), 1),
    (events) => events.push(structuredClone(events.find(({ type, data }) => type === "test:summary" && data.file))),
    (events) => {
      events.find(({ type, data }) => type === "test:summary" && data.file).data.file = path.join(
        repoRoot,
        "scripts",
        "security",
        "lookalike.test.mjs",
      );
    },
    (events) => {
      events.find(({ type, data }) => type === "test:summary" && data.file).data.counts.passed -= 1;
    },
    (events) => {
      events.find(({ type, data }) => type === "test:summary" && data.file === undefined).data.counts.tests -= 1;
    },
    (events) => {
      events.find(({ type, data }) => type === "test:summary" && data.file).data.counts.skipped = 1;
    },
    (events) => {
      events.find(({ type, data }) => type === "test:summary" && data.file).data.counts.cancelled = 1;
    },
    (events) => {
      events.find(({ type, data }) => type === "test:summary" && data.file).data.counts.todo = 1;
    },
    (events) => {
      events.find(({ type, data }) => type === "test:summary" && data.file).data.success = false;
    },
  ];
  for (const mutate of mutations) {
    const events = structuredClone(baseline);
    mutate(events);
    assert.throws(() =>
      validateReleaseAutomationProofEvents(eventSource(events)),
    );
  }
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
    ["apps", "sso", "migrations", "0022_alert_evaluator_run_proof.sql"],
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

test("encrypted archive requires the exact 0021 ledger before runtime source", () => {
  for (const mutation of ["missing", "truncated"]) {
    const fixture = createDependencyFixture();
    try {
      const target = path.join(
        fixture.identityRoot,
        "migrations",
        "0021_audit_archive.sql",
      );
      if (mutation === "missing") renameSync(target, `${target}.lookalike`);
      else writeFileSync(target, 'CREATE TABLE "audit_archive_source" (id integer);');
      assert.equal(
        statusOf(dependencyStatus(fixture), "encrypted_r2_archive"),
        "source_invalid",
      );
    } finally {
      rmSync(fixture.repositoryRoot, { force: true, recursive: true });
    }
  }
});

test("observability evidence requires the exact 0022 run-proof companion", () => {
  for (const mutation of ["missing", "empty", "truncated", "commented"]) {
    const fixture = createDependencyFixture();
    try {
      const target = path.join(
        fixture.identityRoot,
        "migrations",
        "0022_alert_evaluator_run_proof.sql",
      );
      if (mutation === "missing") renameSync(target, `${target}.lookalike`);
      if (mutation === "empty") writeFileSync(target, "");
      if (mutation === "truncated") {
        writeFileSync(target, 'CREATE TABLE "alert_evaluator_run" (id text);');
      }
      if (mutation === "commented") {
        const original = readFileSync(target, "utf8");
        writeFileSync(target, `-- ${original.replaceAll("\n", "\n-- ")}\n`);
      }
      assert.equal(
        statusOf(dependencyStatus(fixture), "observability_0020"),
        mutation === "missing" ? "dependency_missing" : "source_invalid",
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
    ["encrypted_r2_archive", "0021_audit_archive.sql"],
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
