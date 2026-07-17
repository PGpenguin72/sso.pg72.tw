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
  applyAllMigrations,
  assertEquivalentD1,
  collectD1Manifest,
  executeD1,
  executeD1File,
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
import { readinessFromDependencies, writeClosedReport } from "./report.mjs";

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

export function dependencyStatus() {
  const wranglerSource = readFileSync(path.join(ssoRoot, "wrangler.jsonc"), "utf8");
  return [
    {
      name: "global_logout_0018",
      status: existsSync(path.join(ssoRoot, "migrations", "0018_global_logout.sql"))
        ? "present"
        : "dependency_missing",
    },
    {
      name: "recovery_0019",
      status: existsSync(path.join(ssoRoot, "migrations", "0019_recovery_codes.sql"))
        ? "present"
        : "dependency_missing",
    },
    {
      name: "observability_0020",
      status: existsSync(
        path.join(ssoRoot, "migrations", "0020_alert_observability.sql"),
      )
        ? "present"
        : "dependency_missing",
    },
    {
      name: "encrypted_r2_archive",
      status:
        existsSync(path.join(ssoRoot, "worker", "audit-archive.ts")) &&
        /"r2_buckets"\s*:/.test(wranglerSource)
          ? "present"
          : "dependency_missing",
    },
    {
      name: "release_automation",
      status:
        existsSync(path.join(repoRoot, "security", "release-policy.json")) &&
        existsSync(path.join(repoRoot, "scripts", "security", "dast.mjs"))
          ? "present"
          : "dependency_missing",
    },
  ];
}

function runFocusedContinuityTests(homeDirectory) {
  const environment = closedChildEnvironment(homeDirectory);
  runWorkspaceBinary(
    ssoRoot,
    "vitest",
    ["run", "test/public-readiness-continuity.spec.ts"],
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
) {
  await assertPortAvailable(runtime.origin);
  const processState = startLocalWorker(restoreProject, runtime);
  let checks;
  let listenerStopped = false;
  try {
    await waitForLocalWorker(runtime.origin, processState);
    const discoveryResponse = await fetchLocal(
      runtime.origin,
      "/.well-known/openid-configuration",
    );
    assert.equal(discoveryResponse.status, 200);
    const discovery = await boundedJson(discoveryResponse, "OIDC discovery");
    assert.equal(discovery.issuer, runtime.origin);

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
    const counter = queryRows(
      restoreProject,
      `SELECT counter FROM passkey WHERE id = '${PASSKEY_ID}'`,
    );
    assert.equal(Number(counter[0]?.counter), 1);

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

    executeD1(
      restoreProject,
      `UPDATE jwks SET expiresAt = datetime('now', '-61 days')
        WHERE id = 'continuity-signing-key-a'`,
    );
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
  } finally {
    listenerStopped = await stopLocalWorker(processState);
  }
  return { checks, listenerStopped };
}

export async function runContinuityLocal() {
  assertClosedInvocation();
  assertRemoteOperationsDenied();
  loadClosedProfile("continuity");
  const origin = authorizeOwnedLocalOrigin("continuity");
  const temporaryRoot = mkdtempSync(
    path.join(os.tmpdir(), "pgid-public-readiness-continuity-"),
  );
  const sourceProject = path.join(temporaryRoot, "source");
  const restoreProject = path.join(temporaryRoot, "restore");
  const renderedSeed = path.join(temporaryRoot, "continuity-seed.sql");
  const exportFilename = path.join(temporaryRoot, "continuity-export.sql");
  let listenerStopped = true;
  let temporarySqlRemoved = false;
  let report;
  try {
    const betterAuthSecret = randomSecret();
    const fixture = await createContinuityCryptoFixtures(betterAuthSecret);
    const runtime = createLocalProject(restoreProject, "continuity", {
      betterAuthSecret,
    });
    createLocalProject(sourceProject, "continuity", { betterAuthSecret });
    assert.equal(runtime.origin, origin);
    runFocusedContinuityTests(temporaryRoot);
    applyAllMigrations(sourceProject);
    renderContinuitySeed(SEED_TEMPLATE, renderedSeed, fixture);
    chmodSync(renderedSeed, 0o600);
    executeD1File(sourceProject, renderedSeed, "synthetic continuity seed");
    const sourceManifest = collectD1Manifest(sourceProject);
    const sourceRecords = readContinuityRecords(sourceProject);
    exactFixtureChecks(sourceRecords, fixture);
    assert.equal(sourceManifest.migrationHead, "0018_global_logout.sql");
    assert.equal(sourceManifest.integrityOk, true);
    assert.equal(sourceManifest.foreignKeysOk, true);

    const exported = exportD1(sourceProject, exportFilename);
    assert.ok(exported.bytes > 0 && exported.bytes <= 10 * 1024 * 1024);
    executeD1File(restoreProject, exportFilename, "fresh isolated D1 restore");
    rmSync(exportFilename, { force: true });
    temporarySqlRemoved = !existsSync(exportFilename);
    const restoredManifest = collectD1Manifest(restoreProject);
    const restoredRecords = readContinuityRecords(restoreProject);
    assertEquivalentD1(
      sourceManifest,
      restoredManifest,
      sourceRecords,
      restoredRecords,
    );
    verifyConsentContract(restoreProject);

    const runtimeResult = await exerciseRestoredRuntime(
      restoreProject,
      runtime,
      fixture,
      restoredRecords,
    );
    listenerStopped = runtimeResult.listenerStopped;
    const runtimeChecks = runtimeResult.checks;
    assert.ok(runtimeChecks, "restored runtime did not return checks");
    const dependencies = dependencyStatus();
    const readiness = readinessFromDependencies(dependencies);
    const sourceCommit = runLocalCommand("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      environment: closedChildEnvironment(temporaryRoot),
      label: "source commit lookup",
    }).trim();
    const packageManager = JSON.parse(
      readFileSync(path.join(repoRoot, "package.json"), "utf8"),
    ).packageManager;
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
      kind: "continuity",
      migrationHead: sourceManifest.migrationHead,
      mode: "local",
      ready: readiness.ready,
      rowCounts: sourceManifest.rowCounts,
      schema: {
        foreignKeys: "ok",
        integrity: "ok",
        sha256: sourceManifest.schemaSha256,
      },
      schemaVersion: 1,
      sourceCommit,
      status: readiness.status,
      syntheticOnly: true,
      toolVersions: {
        node: process.versions.node,
        pnpm: packageManager.replace(/^pnpm@/, ""),
        wrangler: readPackageVersion(
          path.join(ssoRoot, "node_modules", "wrangler"),
        ),
      },
    };
  } finally {
    rmSync(exportFilename, { force: true });
    rmSync(renderedSeed, { force: true });
    temporarySqlRemoved =
      !existsSync(exportFilename) && !existsSync(renderedSeed);
    removeTemporaryTree(temporaryRoot);
  }

  assert.ok(report, "continuity report was not produced");
  report.cleanup.listenerStopped = listenerStopped;
  report.cleanup.temporarySqlRemoved = temporarySqlRemoved;
  report.cleanup.temporaryStateRemoved = !existsSync(temporaryRoot);
  assert.ok(Object.values(report.cleanup).every(Boolean), "continuity cleanup failed");
  writeClosedReport(REPORT_FILENAME, report);
  if (!report.ready) {
    const missing = report.dependencies
      .filter(({ status }) => status === "dependency_missing")
      .map(({ name }) => name)
      .join(",");
    console.error(`Public readiness remains blocked: dependency_missing (${missing}).`);
    process.exitCode = 1;
  } else {
    console.log("Synthetic local continuity checks passed; owner Preview and production gates remain external.");
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runContinuityLocal().catch((error) => {
    const failureClass =
      error instanceof Error && /^[A-Za-z][A-Za-z0-9]*$/.test(error.name)
        ? error.name
        : "UnknownError";
    console.error(
      `Local continuity command failed before a closed report (${failureClass}).`,
    );
    process.exitCode = 1;
  });
}
