import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { REQUIRED_DEPENDENCY_NAMES } from "./dependency-contracts.mjs";
import {
  DRILL_PROFILE,
  DRILL_REQUESTS_PER_SCENARIO,
  DRILL_SCENARIO_IDS,
} from "./drill-contract.mjs";
import {
  readinessFromDependencies,
  validateClosedReport,
  writeClosedReport,
  writeMinimalFailureReport,
} from "./report.mjs";

function dependencies(status = "dependency_missing") {
  return REQUIRED_DEPENDENCY_NAMES.map((name) => ({ name, status }));
}

function drillReport(overrides = {}) {
  return {
    cleanup: { listenerStopped: true, temporaryStateRemoved: true },
    dependencies: dependencies(),
    failure: { class: "Error", stage: "runtime" },
    invariants: { d1: "not_run", queue: "not_run", r2: "not_run" },
    kind: "drills",
    mode: "local",
    profile: DRILL_PROFILE,
    ready: false,
    redactionPassed: true,
    scenarios: [],
    schemaVersion: 2,
    sourceCommit: "a".repeat(40),
    sourceState: "clean",
    status: "blocked",
    suiteChecks: { globalLogout: false, sso: false, testRp: false },
    syntheticOnly: true,
    ...overrides,
  };
}

function scenario(id, overrides = {}) {
  return {
    errorCount: 0,
    expectedStatusCount: DRILL_REQUESTS_PER_SCENARIO,
    id,
    maxMs: 4,
    p50Ms: 1,
    p95Ms: 2,
    p99Ms: 3,
    requestCount: DRILL_REQUESTS_PER_SCENARIO,
    status: "passed",
    throughputPerSecond: 2,
    timeoutCount: 0,
    unexpectedStatusCount: 0,
    ...overrides,
  };
}

function completedDrillReport(overrides = {}) {
  return drillReport({
    dependencies: dependencies("verified"),
    failure: { class: "none", stage: "none" },
    invariants: { d1: "passed", queue: "passed", r2: "passed" },
    ready: true,
    scenarios: DRILL_SCENARIO_IDS.map((id) => scenario(id)),
    status: "synthetic_pass",
    suiteChecks: { globalLogout: true, sso: true, testRp: true },
    ...overrides,
  });
}

function failedContinuityReport(overrides = {}) {
  const checks = Object.fromEntries(
    [
      "centralSidPreserved",
      "clientMetadataPreserved",
      "clientSecretHashOnly",
      "configuredIssuerMatchesDiscovery",
      "consentRevokedAndRestored",
      "consentUnique",
      "counterAdvanced",
      "currentKeyAccepted",
      "expiredSessionRejected",
      "globalLogoutStatePresent",
      "immutableSubjectPreserved",
      "jwksPrivateKeysDecryptable",
      "jwksRestored",
      "liveSessionAccepted",
      "oldAndNewSignaturesVerified",
      "passkeyAssertionVerified",
      "passkeyPublicKeyPreserved",
      "retiredKeyRejected",
    ].map((name) => [name, false]),
  );
  return {
    checks,
    cleanup: {
      listenerStopped: true,
      temporarySqlRemoved: true,
      temporaryStateRemoved: true,
    },
    dependencies: dependencies(),
    export: { bytes: 0, sha256: "0".repeat(64) },
    failure: { class: "Error", stage: "migrations" },
    kind: "continuity",
    migrationLedger: { count: 0, head: null, sha256: null },
    mode: "local",
    ready: false,
    rowCounts: {},
    schema: {
      foreignKeys: "not_run",
      integrity: "not_run",
      sha256: "0".repeat(64),
    },
    schemaVersion: 2,
    sourceCommit: "a".repeat(40),
    sourceState: "clean",
    status: "blocked",
    syntheticOnly: true,
    toolVersions: { node: "26.0.0", pnpm: "11.5.0", wrangler: "4.110.0" },
    ...overrides,
  };
}

test("test fixtures can never be reported as ready", () => {
  const verified = dependencies("verified");
  assert.deepEqual(readinessFromDependencies(verified), {
    ready: true,
    status: "synthetic_pass",
  });
  assert.deepEqual(readinessFromDependencies(verified, { testFixture: true }), {
    ready: false,
    status: "test_fixture",
  });
  assert.throws(() => readinessFromDependencies([]), /exact ordered contract/);
  assert.throws(
    () => readinessFromDependencies([{ name: "synthetic", status: "verified" }]),
    /exact ordered contract/,
  );
});

test("accepts a closed early-failure continuity report and rejects a ready failure", () => {
  assert.doesNotThrow(() => validateClosedReport(failedContinuityReport()));
  assert.throws(() =>
    validateClosedReport(
      failedContinuityReport({ ready: true, status: "synthetic_pass" }),
    ),
  );
});

test("completed continuity evidence requires a populated migration-ledger summary", () => {
  const completed = failedContinuityReport({
    checks: Object.fromEntries(
      Object.keys(failedContinuityReport().checks).map((name) => [name, true]),
    ),
    dependencies: dependencies("verified"),
    export: { bytes: 1_024, sha256: "a".repeat(64) },
    failure: { class: "none", stage: "none" },
    migrationLedger: {
      count: 19,
      head: "0019_recovery_codes.sql",
      sha256: "b".repeat(64),
    },
    ready: true,
    schema: {
      foreignKeys: "ok",
      integrity: "ok",
      sha256: "c".repeat(64),
    },
    status: "synthetic_pass",
  });
  assert.doesNotThrow(() => validateClosedReport(completed));
  for (const migrationLedger of [
    { count: 0, head: null, sha256: null },
    { count: 18, head: "0018_global_logout.sql", sha256: "b".repeat(64) },
    { count: 19, head: "0019_lookalike.sql", sha256: "b".repeat(64) },
    { count: 19, head: "not-a-migration", sha256: "b".repeat(64) },
    { count: 19, head: "0019_recovery_codes.sql", sha256: "0" },
  ]) {
    assert.throws(() =>
      validateClosedReport({ ...completed, migrationLedger }),
    );
  }
});

test("closed report validation rejects extra fields and sensitive values", () => {
  assert.doesNotThrow(() => validateClosedReport(drillReport()));
  assert.throws(() =>
    validateClosedReport(
      drillReport({
        profile: {
          concurrency: 1,
          durationMs: 100,
          requestsPerSecond: 1,
          totalRequests: 1,
        },
      }),
    ),
  );
  assert.throws(() => validateClosedReport(drillReport({ rawBody: "no" })), /unapproved fields/);
  assert.throws(
    () =>
      validateClosedReport(
        drillReport({ scenarios: [{ id: "bad", result: "person@example.invalid" }] }),
      ),
  );
  assert.throws(
    () =>
      validateClosedReport(
        drillReport({ scenarios: [{ id: "bad", result: "https://example.invalid" }] }),
      ),
  );
  assert.throws(
    () =>
      validateClosedReport(
        drillReport({ scenarios: [{ id: "bad", result: "192.0.2.1" }] }),
      ),
  );
});

test("R2 source presence cannot make an unexecuted drill ready", () => {
  const blockedDependencies = dependencies("verified").map((entry) =>
    entry.name === "encrypted_r2_archive"
      ? { ...entry, status: "source_present_unverified" }
      : entry,
  );
  const report = completedDrillReport({
    dependencies: blockedDependencies,
    invariants: { d1: "passed", queue: "passed", r2: "not_run" },
    ready: false,
    status: "blocked",
  });
  assert.doesNotThrow(() => validateClosedReport(report));
  assert.throws(() =>
    validateClosedReport({
      ...report,
      ready: true,
      status: "synthetic_pass",
    }),
  );
});

test("ready drill evidence requires the exact scenario and request contract", () => {
  const valid = completedDrillReport();
  assert.doesNotThrow(() => validateClosedReport(valid));
  const mutations = [
    [],
    valid.scenarios.slice(0, -1),
    [valid.scenarios[0], valid.scenarios[0], ...valid.scenarios.slice(2)],
    valid.scenarios.map((entry, index) =>
      index === 0
        ? scenario(entry.id, {
            expectedStatusCount: 0,
            requestCount: 0,
            throughputPerSecond: 0,
          })
        : entry,
    ),
    valid.scenarios.map((entry, index) =>
      index === 0
        ? scenario(entry.id, {
            expectedStatusCount: 0,
            requestCount: DRILL_REQUESTS_PER_SCENARIO,
          })
        : entry,
    ),
  ];
  for (const scenarios of mutations) {
    assert.throws(() =>
      validateClosedReport({
        ...valid,
        scenarios,
      }),
    );
  }
});

test("drill evidence rejects inconsistent timing and throughput metrics", () => {
  const valid = completedDrillReport();
  for (const mutation of [
    { p50Ms: 5, p95Ms: 2 },
    { maxMs: DRILL_PROFILE.durationMs + 1_001 },
    { throughputPerSecond: 0 },
    { throughputPerSecond: DRILL_PROFILE.requestsPerSecond + 1 },
  ]) {
    assert.throws(() =>
      validateClosedReport({
        ...valid,
        scenarios: valid.scenarios.map((entry, index) =>
          index === 0 ? { ...entry, ...mutation } : entry,
        ),
      }),
    );
  }
});

test("dirty and unavailable source states are explicit and can never be ready", () => {
  assert.doesNotThrow(() =>
    validateClosedReport(
      failedContinuityReport({ sourceState: "dirty" }),
    ),
  );
  assert.doesNotThrow(() =>
    validateClosedReport(
      failedContinuityReport({ sourceCommit: null, sourceState: "unavailable" }),
    ),
  );
  assert.throws(() =>
    validateClosedReport(
      completedDrillReport({ sourceState: "dirty" }),
    ),
  );
  assert.throws(() =>
    validateClosedReport(
      failedContinuityReport({
        sourceCommit: "0".repeat(40),
        sourceState: "clean",
      }),
    ),
  );
  assert.throws(() =>
    validateClosedReport(
      drillReport({ status: "synthetic_pass" }),
    ),
  );
});

test("writes reports atomically with owner-only permissions", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "pgid-report-test-"));
  const filename = path.join(directory, "report.json");
  try {
    writeClosedReport(filename, drillReport());
    assert.equal(statSync(filename).mode & 0o777, 0o600);
    assert.equal(JSON.parse(readFileSync(filename, "utf8")).status, "blocked");
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("emergency writer bypasses the main schema but keeps a minimal closed report", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "pgid-report-emergency-"));
  const filename = path.join(directory, "report.json");
  try {
    const report = writeMinimalFailureReport(filename, {
      class: "message-with-unapproved-shape",
      stage: "not-a-stage",
    });
    assert.deepEqual(report, {
      failure: { class: "UnknownError", stage: "report" },
      kind: "continuity_failure",
      mode: "local",
      ready: false,
      schemaVersion: 2,
      sourceCommit: null,
      sourceState: "unavailable",
      status: "blocked",
    });
    assert.equal(statSync(filename).mode & 0o777, 0o600);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});
