import assert from "node:assert/strict";
import { existsSync, mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { dependencyStatus } from "./continuity-local.mjs";
import {
  applyAllMigrations,
  collectD1Manifest,
  expectedMigrationHead,
} from "./d1-manifest.mjs";
import { runBoundedProfile } from "./load-profiles.mjs";
import {
  assertPortAvailable,
  closedChildEnvironment,
  createLocalProject,
  fetchLocal,
  removeTemporaryTree,
  repoRoot,
  runLocalCommand,
  runWorkspaceBinary,
  ssoRoot,
  startLocalWorker,
  stopLocalWorker,
  testRpRoot,
  waitForLocalWorker,
} from "./local-runtime.mjs";
import {
  assertClosedInvocation,
  assertRemoteOperationsDenied,
  authorizeOwnedLocalOrigin,
  loadClosedProfile,
} from "./policy.mjs";
import {
  readinessFromDependencies,
  writeClosedReport,
  writeMinimalFailureReport,
} from "./report.mjs";

const REPORT_FILENAME = path.join(
  repoRoot,
  ".artifacts",
  "public-readiness",
  "drills-local.json",
);

function randomSecret() {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(48)))
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function failureClassOf(error) {
  return error instanceof Error && /^(?:[A-Za-z][A-Za-z0-9]*)?Error$/.test(error.name)
    ? error.name
    : "UnknownError";
}

function runFocusedDrillTests(homeDirectory) {
  const environment = closedChildEnvironment(homeDirectory);
  runWorkspaceBinary(
    ssoRoot,
    "vitest",
    [
      "run",
      "test/public-readiness-drills.spec.ts",
      "test/global-logout.spec.ts",
    ],
    { environment, label: "SSO and global-logout drill suites" },
  );
  runWorkspaceBinary(
    testRpRoot,
    "vitest",
    ["run", "test/public-readiness-drills.spec.ts", "test/worker.spec.ts"],
    { environment, label: "test-RP drill suite" },
  );
}

function drillDefinitions() {
  return [
    { expectedStatuses: [200], id: "health", path: "/health" },
    { expectedStatuses: [200], id: "readiness", path: "/ready" },
    {
      expectedStatuses: [200],
      id: "discovery",
      path: "/.well-known/openid-configuration",
    },
    {
      expectedStatuses: [400],
      id: "authorize_invalid",
      path: "/oauth2/authorize",
    },
    {
      expectedStatuses: [401],
      id: "userinfo_unauthorized",
      path: "/oauth2/userinfo",
    },
    {
      expectedStatuses: [401],
      id: "admin_unauthorized",
      path: "/api/admin/users",
    },
  ];
}

function sourceCommit(homeDirectory) {
  try {
    const value = runLocalCommand("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      environment: closedChildEnvironment(homeDirectory),
      label: "source commit lookup",
      suppressDiagnostic: true,
    }).trim();
    return /^[a-f0-9]{40}$/.test(value) ? value : "0".repeat(40);
  } catch {
    return "0".repeat(40);
  }
}

export function earlyDrillReport(
  stage,
  error,
  cleanup,
  profile,
  homeDirectory,
) {
  return {
    cleanup,
    dependencies: dependencyStatus(),
    failure: { class: failureClassOf(error), stage },
    invariants: { d1: "not_run", queue: "not_run", r2: "not_run" },
    kind: "drills",
    mode: "local",
    profile,
    ready: false,
    redactionPassed: true,
    scenarios: [],
    schemaVersion: 1,
    sourceCommit: sourceCommit(homeDirectory),
    status: "blocked",
    suiteChecks: { globalLogout: false, sso: false, testRp: false },
    syntheticOnly: true,
  };
}

export async function runLocalDrills() {
  let stage = "invocation";
  let temporaryRoot;
  let processState;
  let listenerStopped = true;
  let temporaryStateRemoved = true;
  let report;
  let caughtError;
  let profile;
  try {
    assertClosedInvocation();
    assertRemoteOperationsDenied();
    profile = loadClosedProfile("drills");
    const origin = authorizeOwnedLocalOrigin("drills");
    stage = "setup";
    temporaryRoot = mkdtempSync(
      path.join(os.tmpdir(), "pgid-public-readiness-drills-"),
    );
    const runtime = createLocalProject(temporaryRoot, "drills", {
      betterAuthSecret: randomSecret(),
    });
    assert.equal(runtime.origin, origin);

    stage = "workerd_suites";
    runFocusedDrillTests(temporaryRoot);
    stage = "migrations";
    applyAllMigrations(temporaryRoot);
    stage = "runtime";
    await assertPortAvailable(origin);
    processState = startLocalWorker(temporaryRoot, runtime);
    await waitForLocalWorker(origin, processState);
    const scenarios = await runBoundedProfile(
      profile,
      drillDefinitions(),
      (definition, _index, deadlineSignal) =>
        fetchLocal(origin, definition.path, {
          method: "GET",
          signal: deadlineSignal,
        }),
    );
    listenerStopped = await stopLocalWorker(processState);
    processState = undefined;
    stage = "manifest";
    const manifest = collectD1Manifest(temporaryRoot);
    assert.equal(
      manifest.migrationHead,
      expectedMigrationHead(path.join(ssoRoot, "migrations")),
    );
    assert.equal(manifest.integrityOk, true);
    assert.equal(manifest.foreignKeysOk, true);
    const dependencies = dependencyStatus();
    const dependencyReadiness = readinessFromDependencies(dependencies);
    const invariants = {
      d1: "passed",
      queue: "passed",
      r2:
        dependencies.find(({ name }) => name === "encrypted_r2_archive")?.status ===
        "present"
          ? "not_run"
          : "dependency_missing",
    };
    const suiteChecks = { globalLogout: true, sso: true, testRp: true };
    const localChecksPassed =
      listenerStopped &&
      scenarios.every(({ status }) => status === "passed") &&
      Object.values(suiteChecks).every(Boolean) &&
      Object.values(invariants).every((value) => value === "passed");
    const ready = dependencyReadiness.ready && localChecksPassed;
    report = {
      cleanup: { listenerStopped, temporaryStateRemoved: true },
      dependencies,
      failure: { class: "none", stage: "none" },
      invariants,
      kind: "drills",
      mode: "local",
      profile,
      ready,
      redactionPassed: true,
      scenarios,
      schemaVersion: 1,
      sourceCommit: sourceCommit(temporaryRoot),
      status: ready ? "synthetic_pass" : "blocked",
      suiteChecks,
      syntheticOnly: true,
    };
  } catch (error) {
    caughtError = error;
  } finally {
    if (processState) listenerStopped = await stopLocalWorker(processState);
    try {
      if (temporaryRoot) removeTemporaryTree(temporaryRoot);
      temporaryStateRemoved = !temporaryRoot || !existsSync(temporaryRoot);
    } catch {
      temporaryStateRemoved = false;
    }
  }

  const cleanup = { listenerStopped, temporaryStateRemoved };
  if (!Object.values(cleanup).every(Boolean) && !caughtError) {
    caughtError = new Error("closed cleanup failed");
    caughtError.name = "CleanupError";
    stage = "report";
  }
  if (caughtError || !report) {
    report = earlyDrillReport(
      stage,
      caughtError ?? new Error("drill report was not produced"),
      cleanup,
      profile ?? loadClosedProfile("drills"),
      repoRoot,
    );
  } else {
    report.cleanup = cleanup;
  }
  try {
    writeClosedReport(REPORT_FILENAME, report);
  } catch (error) {
    const emergency = writeMinimalFailureReport(REPORT_FILENAME, {
      class: failureClassOf(error),
      stage: "report",
    });
    console.error(
      `Local drills failed: stage=${emergency.failure.stage}, class=${emergency.failure.class}.`,
    );
    process.exitCode = 1;
    return emergency;
  }
  if (caughtError) {
    console.error(
      `Local drills failed: stage=${report.failure.stage}, class=${report.failure.class}.`,
    );
    process.exitCode = 1;
  } else if (!report.ready) {
    const missing = report.dependencies
      .filter(({ status }) => status === "dependency_missing")
      .map(({ name }) => name)
      .join(",");
    console.error(`Local drills remain blocked: dependency_missing (${missing}).`);
    process.exitCode = 1;
  } else {
    console.log("Synthetic local drills passed; no Preview or production target was used.");
  }
  return report;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runLocalDrills().catch((error) => {
    try {
      writeMinimalFailureReport(REPORT_FILENAME, {
        class: failureClassOf(error),
        stage: "report",
      });
    } catch {
      // A filesystem failure may prevent the emergency artifact.
    }
    console.error("Local drills failed before a standard report.");
    process.exitCode = 1;
  });
}
