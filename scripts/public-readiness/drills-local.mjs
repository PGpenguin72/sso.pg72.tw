import assert from "node:assert/strict";
import { existsSync, mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  dependencyStatus,
  runGlobalLogoutDependencyProof,
  runRecoveryDependencyProof,
  runReleaseAutomationDependencyProof,
} from "./dependency-contracts.mjs";
import { DRILL_DEFINITIONS } from "./drill-contract.mjs";
import {
  applyAllMigrations,
  assertIntegratedMigrationLedger,
  collectD1Manifest,
  expectedIntegratedMigrationLedger,
} from "./d1-manifest.mjs";
import { runBoundedProfile } from "./load-profiles.mjs";
import {
  assertPortAvailable,
  closedChildEnvironment,
  createLocalProject,
  fetchLocal,
  inspectSourceState,
  removeTemporaryTree,
  repoRoot,
  requireCleanSource,
  requireStableSource,
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

export function earlyDrillReport(
  stage,
  error,
  cleanup,
  profile,
  source = { sourceCommit: null, sourceState: "unavailable" },
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
    schemaVersion: 2,
    sourceCommit: source.sourceCommit,
    sourceState: source.sourceState,
    status: "blocked",
    suiteChecks: { globalLogout: false, sso: false, testRp: false },
    syntheticOnly: true,
  };
}

export async function runLocalDrills() {
  let stage = "invocation";
  let source = { sourceCommit: null, sourceState: "unavailable" };
  const dependencyProofs = [];
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
    stage = "source";
    source = inspectSourceState({ homeDirectory: repoRoot });
    requireCleanSource(source);
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
    dependencyProofs.push(runGlobalLogoutDependencyProof(temporaryRoot));
    dependencyProofs.push(runRecoveryDependencyProof(temporaryRoot));
    dependencyProofs.push(runReleaseAutomationDependencyProof(temporaryRoot));
    stage = "migrations";
    applyAllMigrations(temporaryRoot);
    stage = "runtime";
    await assertPortAvailable(origin);
    processState = startLocalWorker(temporaryRoot, runtime);
    await waitForLocalWorker(origin, processState);
    const scenarios = await runBoundedProfile(
      profile,
      DRILL_DEFINITIONS,
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
    assert.deepEqual(
      assertIntegratedMigrationLedger(manifest.migrationLedger),
      expectedIntegratedMigrationLedger(path.join(ssoRoot, "migrations")),
    );
    assert.equal(manifest.integrityOk, true);
    assert.equal(manifest.foreignKeysOk, true);
    const dependencies = dependencyStatus({ proofs: dependencyProofs });
    const dependencyReadiness = readinessFromDependencies(dependencies);
    const invariants = {
      d1: "passed",
      queue: "passed",
      r2:
        dependencies.find(({ name }) => name === "encrypted_r2_archive")?.status !==
        "dependency_missing"
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
    stage = "report";
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
      schemaVersion: 2,
      sourceCommit: source.sourceCommit,
      sourceState: source.sourceState,
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
  if (source.sourceState === "clean") {
    const initialSource = source;
    const finalSource = inspectSourceState({ homeDirectory: repoRoot });
    source = finalSource;
    try {
      requireStableSource(initialSource, finalSource);
      if (report) {
        report.sourceCommit = finalSource.sourceCommit;
        report.sourceState = finalSource.sourceState;
      }
    } catch (error) {
      if (!caughtError) {
        caughtError = error;
        stage = "source_finalize";
      }
    }
  }
  if (caughtError || !report) {
    report = earlyDrillReport(
      stage,
      caughtError ?? new Error("drill report was not produced"),
      cleanup,
      profile ?? loadClosedProfile("drills"),
      source,
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
      .filter(({ status }) => status !== "verified")
      .map(({ name, status }) => `${name}:${status}`)
      .join(",");
    console.error(`Local drills remain blocked: dependencies (${missing}).`);
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
