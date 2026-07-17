import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  readinessFromDependencies,
  validateClosedReport,
  writeClosedReport,
  writeMinimalFailureReport,
} from "./report.mjs";

function drillReport(overrides = {}) {
  return {
    cleanup: { listenerStopped: true, temporaryStateRemoved: true },
    dependencies: [{ name: "recovery_0019", status: "dependency_missing" }],
    failure: { class: "none", stage: "none" },
    invariants: { d1: "passed", queue: "passed", r2: "dependency_missing" },
    kind: "drills",
    mode: "local",
    profile: {
      concurrency: 1,
      durationMs: 100,
      requestsPerSecond: 1,
      totalRequests: 1,
    },
    ready: false,
    redactionPassed: true,
    scenarios: [],
    schemaVersion: 1,
    sourceCommit: "a".repeat(40),
    status: "blocked",
    suiteChecks: { globalLogout: true, sso: true, testRp: true },
    syntheticOnly: true,
    ...overrides,
  };
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
    dependencies: [{ name: "recovery_0019", status: "dependency_missing" }],
    export: { bytes: 0, sha256: "0".repeat(64) },
    failure: { class: "Error", stage: "migrations" },
    kind: "continuity",
    migrationHead: "not_run",
    mode: "local",
    ready: false,
    rowCounts: {},
    schema: {
      foreignKeys: "not_run",
      integrity: "not_run",
      sha256: "0".repeat(64),
    },
    schemaVersion: 1,
    sourceCommit: "a".repeat(40),
    status: "blocked",
    syntheticOnly: true,
    toolVersions: { node: "26.0.0", pnpm: "11.5.0", wrangler: "4.110.0" },
    ...overrides,
  };
}

test("test fixtures can never be reported as ready", () => {
  const dependencies = [{ name: "synthetic", status: "present" }];
  assert.deepEqual(readinessFromDependencies(dependencies), {
    ready: true,
    status: "synthetic_pass",
  });
  assert.deepEqual(readinessFromDependencies(dependencies, { testFixture: true }), {
    ready: false,
    status: "test_fixture",
  });
});

test("accepts a closed early-failure continuity report and rejects a ready failure", () => {
  assert.doesNotThrow(() => validateClosedReport(failedContinuityReport()));
  assert.throws(() =>
    validateClosedReport(
      failedContinuityReport({ ready: true, status: "synthetic_pass" }),
    ),
  );
});

test("closed report validation rejects extra fields and sensitive values", () => {
  assert.doesNotThrow(() => validateClosedReport(drillReport()));
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
  const report = drillReport({
    dependencies: [{ name: "encrypted_r2_archive", status: "present" }],
    invariants: { d1: "passed", queue: "passed", r2: "not_run" },
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
      schemaVersion: 1,
      status: "blocked",
    });
    assert.equal(statSync(filename).mode & 0o777, 0o600);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});
