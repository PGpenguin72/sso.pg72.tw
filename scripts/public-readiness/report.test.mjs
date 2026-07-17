import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  readinessFromDependencies,
  validateClosedReport,
  writeClosedReport,
} from "./report.mjs";

function drillReport(overrides = {}) {
  return {
    cleanup: { listenerStopped: true, temporaryStateRemoved: true },
    dependencies: [{ name: "recovery_0019", status: "dependency_missing" }],
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
    syntheticOnly: true,
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

test("closed report validation rejects extra fields and sensitive values", () => {
  assert.doesNotThrow(() => validateClosedReport(drillReport()));
  assert.throws(() => validateClosedReport(drillReport({ rawBody: "no" })), /unapproved fields/);
  assert.throws(
    () =>
      validateClosedReport(
        drillReport({ scenarios: [{ id: "bad", result: "person@example.invalid" }] }),
      ),
    /email-like/,
  );
  assert.throws(
    () =>
      validateClosedReport(
        drillReport({ scenarios: [{ id: "bad", result: "https://example.invalid" }] }),
      ),
    /contains a URL/,
  );
  assert.throws(
    () =>
      validateClosedReport(
        drillReport({ scenarios: [{ id: "bad", result: "192.0.2.1" }] }),
      ),
    /address-like/,
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
