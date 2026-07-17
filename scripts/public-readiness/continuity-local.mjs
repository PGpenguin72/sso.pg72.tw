import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  createContinuityCryptoFixtures,
  createPasskeyAssertion,
  decryptSigningKey,
  renderContinuitySeed,
  sessionCookie,
  signCompactJwt,
  verifyCompactJwtAgainstJwks,
} from "./crypto-fixtures.mjs";
import {
  dependencyStatus,
  runGlobalLogoutDependencyProof,
} from "./dependency-contracts.mjs";
import {
  applyAllMigrations,
  assertEquivalentD1,
  collectD1Manifest,
  executeD1,
  executeD1File,
  expectedMigrationLedger,
  exportD1,
  queryRows,
  readContinuityRecords,
} from "./d1-manifest.mjs";
import {
  assertPortAvailable,
  closedChildEnvironment,
  createLocalProject,
  fetchLocal,
  readPackageVersion,
  removeTemporaryTree,
  repoRoot,
  inspectSourceState,
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

const USER_ID = "10000000-0000-4000-8000-000000000001";
const LIVE_SESSION_ID = "30000000-0000-4000-8000-000000000001";
const PASSKEY_ID = "20000000-0000-4000-8000-000000000001";
const CONSENT_ID = "40000000-0000-4000-8000-000000000001";
const REPORT_FILENAME = path.join(
  repoRoot,
  ".artifacts",
  "public-readiness",
  "continuity-local.json",
);
const SEED_TEMPLATE = fileURLToPath(
  new URL("./fixtures/continuity-seed.sql", import.meta.url),
);

function randomSecret() {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(48)))
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function emptyChecks() {
  return {
    centralSidPreserved: false,
    clientMetadataPreserved: false,
    clientSecretHashOnly: false,
    configuredIssuerMatchesDiscovery: false,
    consentRevokedAndRestored: false,
    consentUnique: false,
    counterAdvanced: false,
    currentKeyAccepted: false,
    expiredSessionRejected: false,
    globalLogoutStatePresent: false,
    immutableSubjectPreserved: false,
    jwksPrivateKeysDecryptable: false,
    jwksRestored: false,
    liveSessionAccepted: false,
    oldAndNewSignaturesVerified: false,
    passkeyAssertionVerified: false,
    passkeyPublicKeyPreserved: false,
    retiredKeyRejected: false,
  };
}

function failureClassOf(error) {
  return error instanceof Error && /^(?:[A-Za-z][A-Za-z0-9]*)?Error$/.test(error.name)
    ? error.name
    : "UnknownError";
}

const CLASSIFIED_STAGE_ERRORS = new Set([
  "ContinuityInvariantError",
  "D1ForeignKeyError",
  "D1IntegrityError",
  "D1ManifestError",
  "D1MigrationLedgerError",
  "D1RecordsError",
  "D1RowCountCardinalityError",
  "D1RowCountColumnsError",
  "D1RowCountError",
  "D1RowCountQueryError",
  "D1RowCountValueError",
  "D1SchemaHashError",
  "D1SchemaQueryError",
  "D1TablePolicyError",
]);
const ROW_COUNT_TABLE_ERROR_PATTERN = /^D1RowCountTable\d{2}Error$/;

function isClassifiedStageError(error) {
  return (
    error instanceof Error &&
    (CLASSIFIED_STAGE_ERRORS.has(error.name) ||
      ROW_COUNT_TABLE_ERROR_PATTERN.test(error.name))
  );
}

export function classifiedStage(errorName, operation) {
  assert.ok(CLASSIFIED_STAGE_ERRORS.has(errorName));
  assert.equal(typeof operation, "function");
  try {
    return operation();
  } catch (cause) {
    if (isClassifiedStageError(cause)) {
      throw cause;
    }
    const error = new Error("closed stage failure");
    error.name = errorName;
    throw error;
  }
}

function toolMetadata() {
  const packageManager = JSON.parse(
    readFileSync(path.join(repoRoot, "package.json"), "utf8"),
  ).packageManager;
  return {
    toolVersions: {
      node: process.versions.node,
      pnpm: packageManager.replace(/^pnpm@/, ""),
      wrangler: readPackageVersion(
        path.join(ssoRoot, "node_modules", "wrangler"),
      ),
    },
  };
}

export function earlyFailureReport(
  stage,
  error,
  cleanup,
  source = { sourceCommit: null, sourceState: "unavailable" },
) {
  const metadata = toolMetadata();
  return {
    checks: emptyChecks(),
    cleanup,
    dependencies: dependencyStatus(),
    export: { bytes: 0, sha256: "0".repeat(64) },
    failure: { class: failureClassOf(error), stage },
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
    sourceCommit: source.sourceCommit,
    sourceState: source.sourceState,
    status: "blocked",
    syntheticOnly: true,
    toolVersions: metadata.toolVersions,
  };
}

function runFocusedContinuityTests(homeDirectory) {
  const environment = closedChildEnvironment(homeDirectory);
  runWorkspaceBinary(
    ssoRoot,
    "vitest",
    [
      "run",
      "test/public-readiness-continuity.spec.ts",
    ],
    { environment, label: "SSO continuity workerd suite" },
  );
  runWorkspaceBinary(
    testRpRoot,
    "vitest",
    ["run", "test/public-readiness-continuity.spec.ts"],
    { environment, label: "test-RP continuity workerd suite" },
  );
}

async function boundedJson(response, label) {
  const declared = Number(response.headers.get("content-length"));
  assert.ok(
    !Number.isFinite(declared) || declared <= 128 * 1024,
    `${label} response is too large`,
  );
  const bytes = new Uint8Array(await response.arrayBuffer());
  assert.ok(bytes.length <= 128 * 1024, `${label} response exceeded its limit`);
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error(`${label} did not return JSON`);
  }
}

function cookieHeaders(cookie, origin) {
  return new Headers({
    "Content-Type": "application/json",
    Cookie: cookie,
    Origin: origin,
  });
}

function exactFixtureChecks(sourceRecords, fixture) {
  const user = sourceRecords.user_record;
  const passkey = sourceRecords.passkey_record;
  const client = sourceRecords.client_record;
  const consent = sourceRecords.consent_record;
  const sessions = sourceRecords.session_records;
  const visits = sourceRecords.visit_records;
  assert.equal(user.id, USER_ID);
  assert.equal(user.emailVerified, 1);
  assert.equal(user.status, "active");
  assert.equal(user.accessLevel, "standard");
  assert.equal(passkey.id, PASSKEY_ID);
  assert.equal(passkey.userId, USER_ID);
  assert.equal(passkey.credentialID, fixture.credentialId);
  assert.equal(passkey.publicKey, fixture.passkeyPublicKey);
  assert.equal(passkey.counter, 0);
  assert.equal(client.clientId, "continuity-rp");
  assert.equal(client.clientSecret, fixture.clientSecretHash);
  assert.equal(client.clientSecret.length, 43);
  assert.notEqual(client.clientSecret, fixture.clientSecretSuffix);
  assert.ok(!client.clientSecret.startsWith("pg72_cs_"));
  assert.equal(client.tokenEndpointAuthMethod, "client_secret_post");
  assert.equal(client.requirePKCE, 1);
  assert.equal(client.skipConsent, 0);
  assert.equal(consent.id, CONSENT_ID);
  assert.equal(consent.clientId, "continuity-rp");
  assert.equal(consent.userId, USER_ID);
  assert.equal(sessions.length, 2);
  assert.ok(sessions.some(({ id }) => id === LIVE_SESSION_ID));
  assert.deepEqual(visits, [
    { client_id: "continuity-rp", session_id: LIVE_SESSION_ID },
  ]);
}

const RUNTIME_FAILURE_CLASSES = Object.freeze({
  counter: "RuntimeCounterError",
  discovery: "RuntimeDiscoveryError",
  first_stop: "RuntimeFirstStopError",
  key_decrypt: "RuntimeKeyDecryptError",
  overlap_jwks: "RuntimeOverlapJwksError",
  overlap_signatures: "RuntimeOverlapSignaturesError",
  passkey_challenge: "RuntimePasskeyChallengeError",
  passkey_verify: "RuntimePasskeyVerifyError",
  retirement_jwks: "RuntimeRetirementJwksError",
  retirement_restart: "RuntimeRetirementRestartError",
  retirement_update: "RuntimeRetirementUpdateError",
  sessions: "RuntimeSessionsError",
  worker_ready: "RuntimeWorkerReadyError",
  worker_start: "RuntimeWorkerStartError",
});

export function closedRuntimeError(step) {
  assert.ok(Object.hasOwn(RUNTIME_FAILURE_CLASSES, step));
  const error = new Error("closed runtime failure");
  error.name = RUNTIME_FAILURE_CLASSES[step];
  return error;
}

function verifyConsentContract(projectDirectory) {
  const unique = queryRows(
    projectDirectory,
    `SELECT COUNT(*) AS count FROM sqlite_schema
      WHERE type = 'index' AND name = 'oauth_consent_user_client_unique'`,
  );
  assert.equal(Number(unique[0]?.count), 1);
  executeD1(projectDirectory, `DELETE FROM oauthConsent WHERE id = '${CONSENT_ID}'`);
  assert.equal(
    Number(
      queryRows(
        projectDirectory,
        `SELECT COUNT(*) AS count FROM oauthConsent WHERE id = '${CONSENT_ID}'`,
      )[0]?.count,
    ),
    0,
  );
  executeD1(
    projectDirectory,
    `INSERT INTO oauthConsent
      (id, clientId, userId, referenceId, scopes, createdAt, updatedAt)
     VALUES (
      '${CONSENT_ID}', 'continuity-rp', '${USER_ID}', NULL,
      '["openid","profile"]', datetime('now'), datetime('now')
     )`,
  );
  assert.equal(
    Number(
      queryRows(
        projectDirectory,
        `SELECT COUNT(*) AS count FROM oauthConsent WHERE id = '${CONSENT_ID}'`,
      )[0]?.count,
    ),
    1,
  );
}

async function exerciseRestoredRuntime(
  restoreProject,
  runtime,
  fixture,
  restoredRecords,
  recordListenerState,
) {
  let processState;
  let checks;
  let listenerStopped = true;
  let runtimeStep = "worker_start";
  const stopCurrentWorker = async () => {
    if (!processState) return;
    const stopped = await stopLocalWorker(processState);
    listenerStopped = listenerStopped && stopped;
    processState = undefined;
    recordListenerState(listenerStopped);
  };
  try {
    await assertPortAvailable(runtime.origin);
    processState = startLocalWorker(restoreProject, runtime);
    runtimeStep = "worker_ready";
    await waitForLocalWorker(runtime.origin, processState);
    runtimeStep = "discovery";
    const discoveryResponse = await fetchLocal(
      runtime.origin,
      "/.well-known/openid-configuration",
    );
    assert.equal(discoveryResponse.status, 200);
    const discovery = await boundedJson(discoveryResponse, "OIDC discovery");
    assert.equal(discovery.issuer, runtime.origin);

    runtimeStep = "sessions";
    const liveCookie = await sessionCookie(
      fixture.liveSessionToken,
      fixture.betterAuthSecret,
    );
    const expiredCookie = await sessionCookie(
      fixture.expiredSessionToken,
      fixture.betterAuthSecret,
    );
    const liveProfile = await fetchLocal(runtime.origin, "/api/account/profile", {
      headers: cookieHeaders(liveCookie, runtime.origin),
    });
    assert.equal(liveProfile.status, 200);
    const expiredProfile = await fetchLocal(runtime.origin, "/api/account/profile", {
      headers: cookieHeaders(expiredCookie, runtime.origin),
    });
    assert.equal(expiredProfile.status, 401);

    runtimeStep = "passkey_challenge";
    const challengeResponse = await fetchLocal(
      runtime.origin,
      "/api/account/passkey-step-up/challenge",
      {
        method: "POST",
        headers: cookieHeaders(liveCookie, runtime.origin),
      },
    );
    assert.equal(challengeResponse.status, 200);
    const challenge = await boundedJson(challengeResponse, "Passkey challenge");
    assert.equal(challenge.options.rpId, "127.0.0.1");
    assert.equal(challenge.options.userVerification, "required");
    const assertion = await createPasskeyAssertion(
      fixture,
      challenge.options.challenge,
      runtime.origin,
    );
    runtimeStep = "passkey_verify";
    const verification = await fetchLocal(
      runtime.origin,
      "/api/account/passkey-step-up/verify",
      {
        method: "POST",
        headers: cookieHeaders(liveCookie, runtime.origin),
        body: JSON.stringify({
          challengeId: challenge.challengeId,
          response: assertion,
        }),
      },
    );
    assert.equal(verification.status, 200);
    runtimeStep = "overlap_jwks";
    const overlapResponse = await fetchLocal(
      runtime.origin,
      "/.well-known/jwks.json",
    );
    assert.equal(overlapResponse.status, 200);
    const overlap = await boundedJson(overlapResponse, "JWKS overlap");
    assert.ok(Array.isArray(overlap.keys));
    assert.deepEqual(
      overlap.keys.map(({ kid }) => kid).sort(),
      [fixture.keyA.id, fixture.keyB.id],
    );
    for (const key of overlap.keys) {
      for (const privateField of ["d", "p", "q", "dp", "dq", "qi", "k"]) {
        assert.equal(key[privateField], undefined);
      }
    }

    runtimeStep = "first_stop";
    await stopCurrentWorker();
    runtimeStep = "counter";
    const counter = queryRows(
      restoreProject,
      `SELECT counter FROM passkey WHERE id = '${PASSKEY_ID}'`,
    );
    assert.equal(Number(counter[0]?.counter), 1);

    runtimeStep = "key_decrypt";
    const restoredKeys = new Map(
      restoredRecords.jwks_records.map((record) => [record.id, record]),
    );
    const privateA = await decryptSigningKey(
      restoredKeys.get(fixture.keyA.id),
      fixture.betterAuthSecret,
    );
    const privateB = await decryptSigningKey(
      restoredKeys.get(fixture.keyB.id),
      fixture.betterAuthSecret,
    );
    const now = Math.floor(Date.now() / 1000);
    const expectedClaims = {
      aud: "https://api.pg72.tw",
      iss: runtime.origin,
      sid: LIVE_SESSION_ID,
      sub: USER_ID,
    };
    const payload = { ...expectedClaims, exp: now + 300, iat: now };
    runtimeStep = "overlap_signatures";
    const oldToken = await signCompactJwt(
      privateA,
      fixture.keyA.id,
      payload,
    );
    const newToken = await signCompactJwt(
      privateB,
      fixture.keyB.id,
      payload,
    );
    assert.equal(
      await verifyCompactJwtAgainstJwks(oldToken, overlap.keys, expectedClaims),
      true,
    );
    assert.equal(
      await verifyCompactJwtAgainstJwks(newToken, overlap.keys, expectedClaims),
      true,
    );

    runtimeStep = "retirement_update";
    executeD1(
      restoreProject,
      `UPDATE jwks SET expiresAt = datetime('now', '-61 days')
        WHERE id = 'continuity-signing-key-a'`,
    );
    runtimeStep = "retirement_restart";
    await assertPortAvailable(runtime.origin);
    processState = startLocalWorker(restoreProject, runtime);
    await waitForLocalWorker(runtime.origin, processState);
    runtimeStep = "retirement_jwks";
    const retiredResponse = await fetchLocal(
      runtime.origin,
      "/.well-known/jwks.json",
    );
    assert.equal(retiredResponse.status, 200);
    const retired = await boundedJson(retiredResponse, "JWKS retirement");
    assert.deepEqual(retired.keys.map(({ kid }) => kid), [fixture.keyB.id]);
    assert.equal(
      await verifyCompactJwtAgainstJwks(oldToken, retired.keys, expectedClaims),
      false,
    );
    assert.equal(
      await verifyCompactJwtAgainstJwks(newToken, retired.keys, expectedClaims),
      true,
    );
    checks = {
      configuredIssuerMatchesDiscovery: true,
      currentKeyAccepted: true,
      expiredSessionRejected: true,
      jwksPrivateKeysDecryptable: true,
      liveSessionAccepted: true,
      oldAndNewSignaturesVerified: true,
      passkeyAssertionVerified: true,
      retiredKeyRejected: true,
    };
  } catch {
    throw closedRuntimeError(runtimeStep);
  } finally {
    await stopCurrentWorker();
  }
  return { checks, listenerStopped };
}

export async function runContinuityLocal() {
  let stage = "invocation";
  let source = { sourceCommit: null, sourceState: "unavailable" };
  const dependencyProofs = [];
  let caughtError;
  let temporaryRoot;
  let sourceProject;
  let restoreProject;
  let renderedSeed;
  let exportFilename;
  let listenerStopped = true;
  let temporarySqlRemoved = true;
  let temporaryStateRemoved = true;
  let report;
  try {
    assertClosedInvocation();
    assertRemoteOperationsDenied();
    loadClosedProfile("continuity");
    const origin = authorizeOwnedLocalOrigin("continuity");
    stage = "source";
    source = inspectSourceState({ homeDirectory: repoRoot });
    requireCleanSource(source);
    stage = "setup";
    temporaryRoot = mkdtempSync(
      path.join(os.tmpdir(), "pgid-public-readiness-continuity-"),
    );
    sourceProject = path.join(temporaryRoot, "source");
    restoreProject = path.join(temporaryRoot, "restore");
    renderedSeed = path.join(temporaryRoot, "continuity-seed.sql");
    exportFilename = path.join(temporaryRoot, "continuity-export.sql");
    const betterAuthSecret = randomSecret();
    const fixture = await createContinuityCryptoFixtures(betterAuthSecret);
    const runtime = createLocalProject(restoreProject, "continuity", {
      betterAuthSecret,
    });
    createLocalProject(sourceProject, "continuity", { betterAuthSecret });
    assert.equal(runtime.origin, origin);
    stage = "workerd_suites";
    runFocusedContinuityTests(temporaryRoot);
    dependencyProofs.push(runGlobalLogoutDependencyProof(temporaryRoot));
    stage = "migrations";
    applyAllMigrations(sourceProject);
    stage = "seed";
    renderContinuitySeed(SEED_TEMPLATE, renderedSeed, fixture);
    chmodSync(renderedSeed, 0o600);
    executeD1File(sourceProject, renderedSeed, "synthetic continuity seed");
    stage = "source_schema";
    const sourceManifest = classifiedStage("D1ManifestError", () =>
      collectD1Manifest(sourceProject),
    );
    stage = "source_records";
    const sourceRecords = classifiedStage("D1RecordsError", () =>
      readContinuityRecords(sourceProject),
    );
    stage = "source_invariants";
    classifiedStage("ContinuityInvariantError", () => {
      exactFixtureChecks(sourceRecords, fixture);
      assert.deepEqual(
        sourceManifest.migrationLedger,
        expectedMigrationLedger(path.join(ssoRoot, "migrations")),
      );
      assert.equal(sourceManifest.integrityOk, true);
      assert.equal(sourceManifest.foreignKeysOk, true);
    });

    stage = "export";
    const exported = exportD1(sourceProject, exportFilename);
    assert.ok(exported.bytes > 0 && exported.bytes <= 10 * 1024 * 1024);
    stage = "restore";
    executeD1File(restoreProject, exportFilename, "fresh isolated D1 restore");
    rmSync(exportFilename, { force: true });
    temporarySqlRemoved = !existsSync(exportFilename);
    stage = "restore_manifest";
    const restoredManifest = collectD1Manifest(restoreProject);
    const restoredRecords = readContinuityRecords(restoreProject);
    assertEquivalentD1(
      sourceManifest,
      restoredManifest,
      sourceRecords,
      restoredRecords,
    );
    stage = "consent";
    verifyConsentContract(restoreProject);

    stage = "runtime";
    const runtimeResult = await exerciseRestoredRuntime(
      restoreProject,
      runtime,
      fixture,
      restoredRecords,
      (stopped) => {
        listenerStopped = stopped;
      },
    );
    listenerStopped = runtimeResult.listenerStopped;
    const runtimeChecks = runtimeResult.checks;
    assert.ok(runtimeChecks, "restored runtime did not return checks");
    const dependencies = dependencyStatus({ proofs: dependencyProofs });
    const readiness = readinessFromDependencies(dependencies);
    stage = "report";
    const metadata = toolMetadata();
    report = {
      checks: {
        centralSidPreserved: sourceRecords.session_records.some(
          ({ id }) => id === LIVE_SESSION_ID,
        ),
        clientMetadataPreserved: true,
        clientSecretHashOnly: true,
        configuredIssuerMatchesDiscovery:
          runtimeChecks.configuredIssuerMatchesDiscovery,
        consentRevokedAndRestored: true,
        consentUnique: true,
        counterAdvanced: true,
        currentKeyAccepted: runtimeChecks.currentKeyAccepted,
        expiredSessionRejected: runtimeChecks.expiredSessionRejected,
        globalLogoutStatePresent: sourceRecords.visit_records.length === 1,
        immutableSubjectPreserved: sourceRecords.user_record.id === USER_ID,
        jwksPrivateKeysDecryptable: runtimeChecks.jwksPrivateKeysDecryptable,
        jwksRestored: restoredRecords.jwks_records.length === 2,
        liveSessionAccepted: runtimeChecks.liveSessionAccepted,
        oldAndNewSignaturesVerified:
          runtimeChecks.oldAndNewSignaturesVerified,
        passkeyAssertionVerified: runtimeChecks.passkeyAssertionVerified,
        passkeyPublicKeyPreserved:
          sourceRecords.passkey_record.publicKey === fixture.passkeyPublicKey,
        retiredKeyRejected: runtimeChecks.retiredKeyRejected,
      },
      cleanup: {
        listenerStopped,
        temporarySqlRemoved,
        temporaryStateRemoved: true,
      },
      dependencies,
      export: exported,
      failure: { class: "none", stage: "none" },
      kind: "continuity",
      migrationLedger: {
        count: sourceManifest.migrationLedger.count,
        head: sourceManifest.migrationLedger.head,
        sha256: sourceManifest.migrationLedger.sha256,
      },
      mode: "local",
      ready: readiness.ready,
      rowCounts: sourceManifest.rowCounts,
      schema: {
        foreignKeys: "ok",
        integrity: "ok",
        sha256: sourceManifest.schemaSha256,
      },
      schemaVersion: 2,
      sourceCommit: source.sourceCommit,
      sourceState: source.sourceState,
      status: readiness.status,
      syntheticOnly: true,
      toolVersions: metadata.toolVersions,
    };
  } catch (error) {
    caughtError = error;
  } finally {
    try {
      if (exportFilename) rmSync(exportFilename, { force: true });
      if (renderedSeed) rmSync(renderedSeed, { force: true });
      temporarySqlRemoved =
        (!exportFilename || !existsSync(exportFilename)) &&
        (!renderedSeed || !existsSync(renderedSeed));
    } catch {
      temporarySqlRemoved = false;
    }
    try {
      if (temporaryRoot) removeTemporaryTree(temporaryRoot);
      temporaryStateRemoved = !temporaryRoot || !existsSync(temporaryRoot);
    } catch {
      temporaryStateRemoved = false;
    }
  }

  const cleanup = {
    listenerStopped,
    temporarySqlRemoved,
    temporaryStateRemoved,
  };
  if (!Object.values(cleanup).every(Boolean) && !caughtError) {
    caughtError = new Error("closed cleanup failed");
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
  if (!report || caughtError) {
    report = earlyFailureReport(
      stage,
      caughtError ?? new Error("continuity report was not produced"),
      cleanup,
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
      `Public readiness failed: stage=${emergency.failure.stage}, class=${emergency.failure.class}.`,
    );
    process.exitCode = 1;
    return emergency;
  }
  if (caughtError) {
    console.error(
      `Public readiness failed: stage=${report.failure.stage}, class=${report.failure.class}.`,
    );
    process.exitCode = 1;
  } else if (!report.ready) {
    const missing = report.dependencies
      .filter(({ status }) => status !== "verified")
      .map(({ name, status }) => `${name}:${status}`)
      .join(",");
    console.error(`Public readiness remains blocked: dependencies (${missing}).`);
    process.exitCode = 1;
  } else {
    console.log("Synthetic local continuity checks passed; owner Preview and production gates remain external.");
  }
  return report;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runContinuityLocal().catch((error) => {
    const failureClass =
      error instanceof Error && /^[A-Za-z][A-Za-z0-9]*$/.test(error.name)
        ? error.name
        : "UnknownError";
    try {
      writeMinimalFailureReport(REPORT_FILENAME, {
        class: failureClass,
        stage: "report",
      });
    } catch {
      // A filesystem failure may prevent even the mode-0600 emergency artifact.
    }
    console.error(
      `Local continuity command failed before a closed report (${failureClass}).`,
    );
    process.exitCode = 1;
  });
}
