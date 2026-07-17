import assert from "node:assert/strict";
import {
  chmodSync,
  mkdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

const TOP_LEVEL_KEYS = {
  continuity: [
    "checks",
    "cleanup",
    "dependencies",
    "export",
    "failure",
    "kind",
    "migrationHead",
    "mode",
    "ready",
    "rowCounts",
    "schema",
    "schemaVersion",
    "sourceCommit",
    "status",
    "syntheticOnly",
    "toolVersions",
  ],
  drills: [
    "cleanup",
    "dependencies",
    "failure",
    "invariants",
    "kind",
    "mode",
    "profile",
    "ready",
    "redactionPassed",
    "scenarios",
    "schemaVersion",
    "sourceCommit",
    "status",
    "suiteChecks",
    "syntheticOnly",
  ],
};
const CONTINUITY_CHECK_KEYS = [
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
];
const CONTINUITY_FAILURE_STAGES = new Set([
  "none",
  "invocation",
  "setup",
  "workerd_suites",
  "migrations",
  "seed",
  "source_manifest",
  "source_schema",
  "source_records",
  "source_invariants",
  "export",
  "restore",
  "restore_manifest",
  "consent",
  "runtime",
  "report",
]);
const DRILL_FAILURE_STAGES = new Set([
  "none",
  "invocation",
  "setup",
  "workerd_suites",
  "migrations",
  "runtime",
  "manifest",
  "report",
]);

function sortedKeys(value) {
  return Object.keys(value).sort();
}

function exactKeys(value, expected, label) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert.deepEqual(sortedKeys(value), [...expected].sort(), `${label} has unapproved fields`);
}

function scanValues(value, label = "report") {
  if (typeof value === "string") {
    assert.ok(!value.includes("@"), `${label} contains an email-like value`);
    assert.ok(!value.includes("://"), `${label} contains a URL`);
    assert.ok(
      !/(?:^|\D)(?:\d{1,3}\.){3}\d{1,3}(?:\D|$)/.test(value) &&
        !value.includes("[::"),
      `${label} contains an address-like value`,
    );
    assert.ok(
      !/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(value),
      `${label} contains a JWT-like value`,
    );
    assert.ok(!/[\r\n]/.test(value), `${label} contains a multiline value`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => scanValues(entry, `${label}[${index}]`));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      scanValues(child, `${label}.${key}`);
    }
  }
}

function validateDependencies(dependencies) {
  assert.ok(Array.isArray(dependencies));
  for (const dependency of dependencies) {
    exactKeys(dependency, ["name", "status"], "dependency");
    assert.match(dependency.name, /^[a-z0-9_]+$/);
    assert.ok(
      dependency.status === "present" || dependency.status === "dependency_missing",
      "dependency status is not allowlisted",
    );
  }
}

export function readinessFromDependencies(
  dependencies,
  { testFixture = false } = {},
) {
  validateDependencies(dependencies);
  const complete = dependencies.every(({ status }) => status === "present");
  return {
    ready: complete && !testFixture,
    status: complete && !testFixture ? "synthetic_pass" : testFixture ? "test_fixture" : "blocked",
  };
}

export function validateClosedReport(report) {
  assert.ok(report?.kind === "continuity" || report?.kind === "drills");
  exactKeys(report, TOP_LEVEL_KEYS[report.kind], report.kind);
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.mode, "local");
  assert.equal(report.syntheticOnly, true);
  assert.equal(typeof report.ready, "boolean");
  assert.ok(["blocked", "synthetic_pass", "test_fixture"].includes(report.status));
  assert.match(report.sourceCommit, /^[a-f0-9]{40}$/);
  validateDependencies(report.dependencies);
  if (report.kind === "continuity") {
    exactKeys(report.checks, CONTINUITY_CHECK_KEYS, "continuity.checks");
    for (const value of Object.values(report.checks)) assert.equal(typeof value, "boolean");
    exactKeys(
      report.cleanup,
      ["listenerStopped", "temporarySqlRemoved", "temporaryStateRemoved"],
      "continuity.cleanup",
    );
    exactKeys(report.export, ["bytes", "sha256"], "continuity.export");
    exactKeys(report.failure, ["class", "stage"], "continuity.failure");
    exactKeys(
      report.schema,
      ["foreignKeys", "integrity", "sha256"],
      "continuity.schema",
    );
    exactKeys(report.toolVersions, ["node", "pnpm", "wrangler"], "continuity.toolVersions");
    assert.match(report.export.sha256, /^[a-f0-9]{64}$/);
    assert.match(report.schema.sha256, /^[a-f0-9]{64}$/);
    assert.match(
      report.failure.class,
      /^(?:none|(?:[A-Za-z][A-Za-z0-9]*)?Error)$/,
    );
    assert.ok(CONTINUITY_FAILURE_STAGES.has(report.failure.stage));
    assert.ok(Number.isSafeInteger(report.export.bytes) && report.export.bytes >= 0);
    assert.ok(["not_run", "ok"].includes(report.schema.integrity));
    assert.ok(["not_run", "ok"].includes(report.schema.foreignKeys));
    if (report.failure.stage === "none") {
      assert.equal(report.failure.class, "none");
      assert.ok(report.export.bytes > 0);
      assert.equal(report.schema.integrity, "ok");
      assert.equal(report.schema.foreignKeys, "ok");
    } else {
      assert.equal(report.ready, false);
      assert.equal(report.status, "blocked");
    }
    for (const [table, count] of Object.entries(report.rowCounts)) {
      assert.match(table, /^[A-Za-z_][A-Za-z0-9_]*$/);
      assert.ok(Number.isSafeInteger(count) && count >= 0);
    }
  } else {
    exactKeys(
      report.cleanup,
      ["listenerStopped", "temporaryStateRemoved"],
      "drills.cleanup",
    );
    exactKeys(
      report.profile,
      ["concurrency", "durationMs", "requestsPerSecond", "totalRequests"],
      "drills.profile",
    );
    exactKeys(report.failure, ["class", "stage"], "drills.failure");
    assert.match(
      report.failure.class,
      /^(?:none|(?:[A-Za-z][A-Za-z0-9]*)?Error)$/,
    );
    assert.ok(DRILL_FAILURE_STAGES.has(report.failure.stage));
    for (const value of Object.values(report.profile)) {
      assert.ok(Number.isSafeInteger(value) && value > 0);
    }
    assert.equal(typeof report.redactionPassed, "boolean");
    exactKeys(report.invariants, ["d1", "queue", "r2"], "drills.invariants");
    exactKeys(
      report.suiteChecks,
      ["globalLogout", "sso", "testRp"],
      "drills.suiteChecks",
    );
    for (const value of Object.values(report.suiteChecks)) {
      assert.equal(typeof value, "boolean");
    }
    for (const value of Object.values(report.invariants)) {
      assert.ok(
        value === "passed" ||
          value === "dependency_missing" ||
          value === "not_run",
      );
    }
    assert.ok(Array.isArray(report.scenarios));
    for (const scenario of report.scenarios) {
      exactKeys(
        scenario,
        [
          "errorCount",
          "expectedStatusCount",
          "id",
          "maxMs",
          "p50Ms",
          "p95Ms",
          "p99Ms",
          "requestCount",
          "status",
          "throughputPerSecond",
          "timeoutCount",
          "unexpectedStatusCount",
        ],
        "drills.scenario",
      );
      assert.match(scenario.id, /^[a-z][a-z0-9_]{0,63}$/);
      assert.ok(scenario.status === "passed" || scenario.status === "failed");
      for (const [name, value] of Object.entries(scenario)) {
        if (["id", "status"].includes(name)) continue;
        assert.ok(Number.isFinite(value) && value >= 0, `${name} must be non-negative`);
      }
    }
    if (report.failure.stage === "none") {
      assert.equal(report.failure.class, "none");
    } else {
      assert.equal(report.ready, false);
      assert.equal(report.status, "blocked");
    }
  }
  if (report.ready) {
    assert.equal(report.status, "synthetic_pass");
    assert.ok(report.dependencies.every(({ status }) => status === "present"));
    if (report.kind === "continuity") {
      assert.ok(Object.values(report.checks).every(Boolean));
    } else {
      assert.ok(report.redactionPassed);
      assert.ok(Object.values(report.suiteChecks).every(Boolean));
      assert.ok(Object.values(report.invariants).every((value) => value === "passed"));
      assert.ok(report.scenarios.every(({ status }) => status === "passed"));
    }
  }
  scanValues(report);
  return report;
}

export function writeClosedReport(filename, report) {
  validateClosedReport(report);
  mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  const temporary = `${filename}.tmp-${process.pid}`;
  try {
    writeFileSync(temporary, `${JSON.stringify(report, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    chmodSync(temporary, 0o600);
    renameSync(temporary, filename);
    chmodSync(filename, 0o600);
  } finally {
    rmSync(temporary, { force: true });
  }
}

export function writeMinimalFailureReport(filename, failure) {
  const stage = CONTINUITY_FAILURE_STAGES.has(failure?.stage)
    ? failure.stage
    : "report";
  const failureClass = /^(?:(?:[A-Za-z][A-Za-z0-9]*)?Error)$/.test(
    failure?.class ?? "",
  )
    ? failure.class
    : "UnknownError";
  const report = {
    failure: { class: failureClass, stage },
    kind: "continuity_failure",
    mode: "local",
    ready: false,
    schemaVersion: 1,
    status: "blocked",
  };
  mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  const temporary = `${filename}.emergency-${process.pid}`;
  try {
    writeFileSync(temporary, `${JSON.stringify(report, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    chmodSync(temporary, 0o600);
    renameSync(temporary, filename);
    chmodSync(filename, 0o600);
  } finally {
    rmSync(temporary, { force: true });
  }
  return report;
}
