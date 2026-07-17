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
    "kind",
    "mode",
    "profile",
    "ready",
    "redactionPassed",
    "scenarios",
    "schemaVersion",
    "sourceCommit",
    "status",
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
    exactKeys(
      report.schema,
      ["foreignKeys", "integrity", "sha256"],
      "continuity.schema",
    );
    exactKeys(report.toolVersions, ["node", "pnpm", "wrangler"], "continuity.toolVersions");
    assert.match(report.export.sha256, /^[a-f0-9]{64}$/);
    assert.match(report.schema.sha256, /^[a-f0-9]{64}$/);
    assert.ok(Number.isSafeInteger(report.export.bytes) && report.export.bytes > 0);
    assert.equal(report.schema.integrity, "ok");
    assert.equal(report.schema.foreignKeys, "ok");
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
    assert.ok(Array.isArray(report.scenarios));
  }
  if (report.ready) {
    assert.equal(report.status, "synthetic_pass");
    assert.ok(report.dependencies.every(({ status }) => status === "present"));
    if (report.kind === "continuity") {
      assert.ok(Object.values(report.checks).every(Boolean));
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
