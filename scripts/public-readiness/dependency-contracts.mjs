import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
} from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parse as parseJsoncText } from "jsonc-parser";

import {
  closedChildEnvironment,
  repoRoot,
  runLocalCommand,
  runWorkspaceBinary,
  ssoRoot,
} from "./local-runtime.mjs";

const requireFromSso = createRequire(path.join(ssoRoot, "package.json"));
const [{ API }, { createVirtualFileSystem }, { SyntaxKind }] = await Promise.all([
  import(
    pathToFileURL(requireFromSso.resolve("typescript/unstable/sync")).href
  ),
  import(
    pathToFileURL(requireFromSso.resolve("typescript/unstable/fs")).href
  ),
  import(
    pathToFileURL(requireFromSso.resolve("typescript/unstable/ast")).href
  ),
]);
const virtualFileSystem = createVirtualFileSystem({});
const compiler = new API({ cwd: "/", fs: virtualFileSystem });
let parsedSourceSequence = 0;
let previousParsedSource = null;
const dependencyProofs = new WeakMap();
const GLOBAL_LOGOUT_TEST_COUNT = 25;
const GLOBAL_LOGOUT_SUITE_COUNT = 2;
const RECOVERY_TEST_COUNT = 20;
const RECOVERY_SUITE_COUNT = 4;
const RECOVERY_ANCESTOR_COUNTS = Object.freeze({
  "recovery Passkey completion": 4,
  "recovery code management": 7,
  "restricted recovery entry": 9,
});
const RELEASE_SECURITY_TESTS = Object.freeze([
  Object.freeze({ filename: "accepted-advisories.test.mjs", count: 5 }),
  Object.freeze({ filename: "artifact-gate.test.mjs", count: 11 }),
  Object.freeze({ filename: "dast.test.mjs", count: 6 }),
  Object.freeze({ filename: "dependency-inventory.test.mjs", count: 2 }),
  Object.freeze({ filename: "release-identity.test.mjs", count: 13 }),
  Object.freeze({ filename: "secret-family.test.mjs", count: 20 }),
  Object.freeze({ filename: "secret-scan.test.mjs", count: 2 }),
  Object.freeze({ filename: "workflow-config.test.mjs", count: 25 }),
  Object.freeze({ filename: "wrangler-config.test.mjs", count: 5 }),
]);
const RELEASE_TEST_COUNT = RELEASE_SECURITY_TESTS.reduce(
  (sum, { count }) => sum + count,
  0,
);
const RELEASE_AUTOMATION_FINGERPRINT_FILES = Object.freeze([
  ".github/workflows/ci.yml",
  ".github/workflows/dast-preview.yml",
  ".oxlintrc.json",
  ".secretlintrc.json",
  "apps/sso/package.json",
  "apps/sso/wrangler.jsonc",
  "apps/test-rp/package.json",
  "apps/test-rp/wrangler.jsonc",
  "package.json",
  "patches/@better-auth__oauth-provider@1.6.23.patch",
  "patches/README.md",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  "scripts/public-readiness/dependency-contracts.mjs",
  "scripts/public-readiness/exact-test-reporter.mjs",
  "scripts/public-readiness/local-runtime.mjs",
  "scripts/security/accepted-advisories.mjs",
  "scripts/security/accepted-advisories.test.mjs",
  "scripts/security/artifact-gate.mjs",
  "scripts/security/artifact-gate.test.mjs",
  "scripts/security/dast-local.mjs",
  "scripts/security/dast.mjs",
  "scripts/security/dast.test.mjs",
  "scripts/security/dependency-inventory.mjs",
  "scripts/security/dependency-inventory.test.mjs",
  "scripts/security/install-tools.mjs",
  "scripts/security/release-identity.mjs",
  "scripts/security/release-identity.test.mjs",
  "scripts/security/secret-family.mjs",
  "scripts/security/secret-family.test.mjs",
  "scripts/security/secret-scan.mjs",
  "scripts/security/secret-scan.test.mjs",
  "scripts/security/typescript-static-values.mjs",
  "scripts/security/workflow-config.mjs",
  "scripts/security/workflow-config.test.mjs",
  "scripts/security/wrangler-config.mjs",
  "scripts/security/wrangler-config.test.mjs",
  "security/accepted-advisories.json",
  "security/dast-policy.json",
  "security/public-readiness-policy.json",
  "security/release-policy.json",
  "security/secret-inventory.json",
  "security/tool-versions.json",
  "security/workflow-policy.json",
  "wiki/package.json",
]);
const SSO_EXECUTION_PATHS = Object.freeze([
  "apps/sso",
  "package.json",
  "patches",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
]);

export const REQUIRED_DEPENDENCY_NAMES = Object.freeze([
  "global_logout_0018",
  "recovery_0019",
  "observability_0020",
  "encrypted_r2_archive",
  "release_automation",
]);

export const DEPENDENCY_STATUSES = Object.freeze([
  "dependency_missing",
  "source_invalid",
  "source_present_unverified",
  "verified",
]);

const SQL_CONTRACTS = Object.freeze({
  global_logout_0018: {
    filename: path.join("migrations", "0018_global_logout.sql"),
    markers: [
      /alter table\s+"logout_delivery"\s+rename to\s+"logout_delivery_legacy_0018"/i,
      /create table\s+"rp_session_client"/i,
      /create table\s+"logout_delivery"/i,
      /create table\s+"logout_delivery_attempt"/i,
      /create trigger\s+"oauth_access_token_record_rp_visit"/i,
    ],
  },
  recovery_0019: {
    filename: path.join("migrations", "0019_recovery_codes.sql"),
    markers: [
      /create table\s+"recovery_code_set"/i,
      /create table\s+"recovery_code"/i,
      /create table\s+"recovery_session"/i,
      /create table\s+"recovery_passkey_challenge"/i,
      /create unique index\s+"passkey_credential_id_unique_idx"/i,
      /create trigger\s+"user_recovery_session_suspension_cleanup"/i,
    ],
  },
  observability_0020: {
    filename: path.join("migrations", "0020_alert_observability.sql"),
    markers: [
      /alter table\s+"audit_event"\s+add column\s+"actor_ref"/i,
      /"actor_ref_hash_version"\s+integer/i,
      /alter table\s+"oauth_client_report"\s+add column\s+"reporter_ref"/i,
      /"reporter_ref_hash_version"\s+integer/i,
      /create table\s+"alert_hash_key_sentinel"/i,
      /create trigger\s+"alert_hash_key_sentinel_insert_guard"/i,
      /create trigger\s+"audit_event_actor_identity_update_guard"/i,
      /create trigger\s+"oauth_client_report_identity_update_guard"/i,
      /create table\s+"alert_state"/i,
      /create table\s+"security_alert"/i,
      /create table\s+"alert_outbox"/i,
      /create table\s+"alert_delivery_attempt"/i,
      /create table\s+"alert_runtime_status"/i,
      /"minimum_numerator_count"\s+integer/i,
      /"last_notification_scheduled_at"\s+date/i,
      /"consecutive_nonzero_samples"\s+integer/i,
      /create unique index\s+"alert_state_semantic_identity_idx"/i,
      /create unique index\s+"security_alert_unresolved_state_idx"/i,
      /create index\s+"alert_outbox_due_idx"/i,
      /create trigger\s+"alert_state_initial_guard"/i,
      /create trigger\s+"alert_state_transition_guard"/i,
      /create trigger\s+"security_alert_insert_state_guard"/i,
      /create trigger\s+"alert_outbox_reminder_sequence_guard"/i,
      /create trigger\s+"alert_delivery_attempt_insert_guard"/i,
      /create trigger\s+"alert_delivery_attempt_transition_guard"/i,
      /create trigger\s+"alert_runtime_status_transition_guard"/i,
      /create index\s+"audit_event_type_subject_time_bounded_idx"/i,
      /create index\s+"audit_event_time_bounded_idx"/i,
      /create index\s+"audit_event_type_actor_time_bounded_idx"/i,
      /create index\s+"audit_event_type_time_bounded_idx"/i,
      /create index\s+"oauth_client_report_time_client_reason_reporter_bounded_idx"/i,
      /create index\s+"logout_delivery_time_client_status_bounded_idx"/i,
      /create index\s+"logout_delivery_status_client_time_bounded_idx"/i,
      /create index\s+"logout_delivery_attempt_completion_bounded_idx"/i,
    ],
  },
});

function fileState(filename) {
  if (!existsSync(filename)) return { state: "missing" };
  try {
    const stat = lstatSync(filename);
    if (!stat.isFile() || stat.size === 0 || stat.size > 2 * 1024 * 1024) {
      return { state: "invalid" };
    }
    return { state: "present", text: readFileSync(filename, "utf8") };
  } catch {
    return { state: "invalid" };
  }
}

function allFilesPresent(filenames) {
  const states = filenames.map(fileState);
  if (states.some(({ state }) => state === "missing")) {
    return { state: "dependency_missing" };
  }
  if (states.some(({ state }) => state !== "present")) {
    return { state: "source_invalid" };
  }
  return { state: "present", files: states };
}

function sqlWithoutComments(text) {
  let result = "";
  let state = "code";
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    const next = text[index + 1];
    if (state === "line_comment") {
      if (character === "\n") {
        result += character;
        state = "code";
      } else {
        result += " ";
      }
      continue;
    }
    if (state === "block_comment") {
      if (character === "*" && next === "/") {
        result += "  ";
        index += 1;
        state = "code";
      } else {
        result += character === "\n" ? "\n" : " ";
      }
      continue;
    }
    if (state === "single_quote") {
      result += character === "\n" ? "\n" : " ";
      if (character === "'" && next === "'") {
        result += " ";
        index += 1;
      } else if (character === "'") {
        state = "code";
      }
      continue;
    }
    if (state === "double_quote") {
      result += character;
      if (character === '"' && next === '"') {
        result += next;
        index += 1;
      } else if (character === '"') {
        state = "code";
      }
      continue;
    }
    if (character === "-" && next === "-") {
      result += "  ";
      index += 1;
      state = "line_comment";
    } else if (character === "/" && next === "*") {
      result += "  ";
      index += 1;
      state = "block_comment";
    } else {
      result += character;
      if (character === "'") state = "single_quote";
      if (character === '"') state = "double_quote";
    }
  }
  return result;
}

function sqlContractState(identityRoot, contract) {
  const filename = path.join(identityRoot, contract.filename);
  const source = allFilesPresent([filename]);
  if (source.state !== "present") return source.state;
  const text = sqlWithoutComments(source.files[0].text);
  return contract.markers.every((marker) => marker.test(text))
    ? "source_present_unverified"
    : "source_invalid";
}

function sqlContractFingerprint(identityRoot, contract) {
  const source = fileState(path.join(identityRoot, contract.filename));
  assert.equal(source.state, "present");
  return createHash("sha256").update(source.text).digest("hex");
}

const STABLE_FILE_STAT_FIELDS = Object.freeze([
  "dev",
  "ino",
  "size",
  "mtimeNs",
  "ctimeNs",
]);

function assertSameNode(before, after, label) {
  assert.equal(after.dev, before.dev, `${label} changed device`);
  assert.equal(after.ino, before.ino, `${label} changed inode`);
}

function assertStableRegularFile(before, after, label) {
  assert.ok(before.isFile(), `${label} is not a regular file`);
  assert.ok(after.isFile(), `${label} stopped being a regular file`);
  for (const field of STABLE_FILE_STAT_FIELDS) {
    assert.equal(after[field], before[field], `${label} changed ${field}`);
  }
}

function isContainedPath(root, candidate) {
  const relative = path.relative(root, candidate);
  return (
    relative !== "" &&
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

function inspectFingerprintRoot(root) {
  assert.equal(typeof root, "string", "fingerprint root must be a path");
  assert.ok(root.length > 0, "fingerprint root must not be empty");
  const lexicalRoot = path.resolve(root);
  const lexicalStat = lstatSync(lexicalRoot, { bigint: true });
  assert.ok(
    lexicalStat.isDirectory() && !lexicalStat.isSymbolicLink(),
    "fingerprint root must be an exact directory",
  );
  const canonicalRoot = realpathSync(lexicalRoot);
  const currentStat = statSync(lexicalRoot, { bigint: true });
  assert.ok(currentStat.isDirectory(), "fingerprint root is not a directory");
  assertSameNode(lexicalStat, currentStat, "fingerprint root");
  assert.equal(
    realpathSync(lexicalRoot),
    canonicalRoot,
    "fingerprint root changed while it was inspected",
  );
  return {
    canonicalRoot,
    dev: currentStat.dev,
    ino: currentStat.ino,
    lexicalRoot,
  };
}

function assertSameFingerprintRoot(before, after) {
  assert.equal(after.lexicalRoot, before.lexicalRoot);
  assert.equal(
    after.canonicalRoot,
    before.canonicalRoot,
    "fingerprint root canonical path changed",
  );
  assertSameNode(before, after, "fingerprint root");
}

function validateFingerprintRelativePath(relative) {
  assert.equal(typeof relative, "string", "fingerprint path must be a string");
  assert.ok(relative.length > 0, "fingerprint path must not be empty");
  assert.equal(path.isAbsolute(relative), false, "fingerprint path must be relative");
  assert.equal(
    path.win32.isAbsolute(relative),
    false,
    "fingerprint path must not be an absolute Windows path",
  );
  assert.equal(
    relative.includes("\\"),
    false,
    "fingerprint path must use repository separators",
  );
  const segments = relative.split("/");
  assert.equal(
    segments.includes(".."),
    false,
    "fingerprint path escaped its repository root",
  );
  assert.ok(
    segments.every((segment) => segment.length > 0 && segment !== "."),
    "fingerprint path must be normalized",
  );
  assert.equal(
    path.posix.normalize(relative),
    relative,
    "fingerprint path must be normalized",
  );
  return segments;
}

function inspectFingerprintAncestors(rootSnapshot, segments, relative) {
  const ancestors = [];
  let current = rootSnapshot.lexicalRoot;
  for (const segment of segments.slice(0, -1)) {
    current = path.join(current, segment);
    const lexicalStat = lstatSync(current, { bigint: true });
    assert.ok(
      lexicalStat.isDirectory() && !lexicalStat.isSymbolicLink(),
      `${relative} has a non-directory or symbolic-link ancestor`,
    );
    const canonical = realpathSync(current);
    assert.ok(
      isContainedPath(rootSnapshot.canonicalRoot, canonical),
      `${relative} has an ancestor outside its canonical root`,
    );
    const currentStat = statSync(current, { bigint: true });
    assert.ok(currentStat.isDirectory(), `${relative} has a non-directory ancestor`);
    assertSameNode(lexicalStat, currentStat, `${relative} ancestor`);
    assert.equal(
      realpathSync(current),
      canonical,
      `${relative} ancestor changed while it was inspected`,
    );
    ancestors.push({ canonical, dev: currentStat.dev, ino: currentStat.ino });
  }
  return ancestors;
}

function assertSameFingerprintAncestors(before, after, relative) {
  assert.equal(after.length, before.length, `${relative} ancestor set changed`);
  for (let index = 0; index < before.length; index += 1) {
    assert.equal(
      after[index].canonical,
      before[index].canonical,
      `${relative} ancestor canonical path changed`,
    );
    assertSameNode(before[index], after[index], `${relative} ancestor`);
  }
}

function inspectOpenedFingerprintFile(
  filename,
  canonicalRoot,
  openedStat,
  relative,
) {
  const lexicalStat = lstatSync(filename, { bigint: true });
  assert.ok(
    lexicalStat.isFile() && !lexicalStat.isSymbolicLink(),
    `${relative} is not an exact regular file`,
  );
  assertStableRegularFile(openedStat, lexicalStat, relative);
  const canonical = realpathSync(filename);
  assert.ok(
    isContainedPath(canonicalRoot, canonical),
    `${relative} escaped its canonical root`,
  );
  const currentStat = statSync(filename, { bigint: true });
  assertStableRegularFile(openedStat, currentStat, relative);
  assert.equal(
    realpathSync(filename),
    canonical,
    `${relative} canonical path changed while it was inspected`,
  );
  const finalStat = lstatSync(filename, { bigint: true });
  assert.ok(!finalStat.isSymbolicLink(), `${relative} became a symbolic link`);
  assertStableRegularFile(openedStat, finalStat, relative);
  return canonical;
}

function readExactFingerprintFile(rootSnapshot, relative, segments) {
  const filename = path.resolve(rootSnapshot.lexicalRoot, ...segments);
  assert.ok(
    isContainedPath(rootSnapshot.lexicalRoot, filename),
    `${relative} escaped its lexical root`,
  );
  const ancestorsBefore = inspectFingerprintAncestors(
    rootSnapshot,
    segments,
    relative,
  );
  const lexicalStat = lstatSync(filename, { bigint: true });
  assert.ok(
    lexicalStat.isFile() && !lexicalStat.isSymbolicLink(),
    `${relative} is not an exact regular file`,
  );

  const noFollow = Number.isInteger(fsConstants.O_NOFOLLOW)
    ? fsConstants.O_NOFOLLOW
    : 0;
  const fileDescriptor = openSync(filename, fsConstants.O_RDONLY | noFollow);
  try {
    const beforeRead = fstatSync(fileDescriptor, { bigint: true });
    assertStableRegularFile(lexicalStat, beforeRead, relative);
    const canonicalBefore = inspectOpenedFingerprintFile(
      filename,
      rootSnapshot.canonicalRoot,
      beforeRead,
      relative,
    );
    const bytes = readFileSync(fileDescriptor);
    const afterRead = fstatSync(fileDescriptor, { bigint: true });
    assertStableRegularFile(beforeRead, afterRead, relative);
    assert.equal(
      BigInt(bytes.length),
      afterRead.size,
      `${relative} read length differs from its opened file size`,
    );
    assert.equal(
      inspectOpenedFingerprintFile(
        filename,
        rootSnapshot.canonicalRoot,
        afterRead,
        relative,
      ),
      canonicalBefore,
      `${relative} canonical path changed while it was read`,
    );
    const ancestorsAfter = inspectFingerprintAncestors(
      rootSnapshot,
      segments,
      relative,
    );
    assertSameFingerprintAncestors(ancestorsBefore, ancestorsAfter, relative);
    assertSameFingerprintRoot(rootSnapshot, inspectFingerprintRoot(rootSnapshot.lexicalRoot));
    return bytes;
  } finally {
    closeSync(fileDescriptor);
  }
}

export function exactFileSetFingerprint(root, filenames) {
  assert.ok(Array.isArray(filenames), "fingerprint paths must be an array");
  assert.ok(filenames.length > 0, "fingerprint path set must not be empty");
  assert.deepEqual(
    filenames,
    [...new Set(filenames)].sort(),
    "fingerprint path set must be exact, unique, and ordered",
  );
  const rootSnapshot = inspectFingerprintRoot(root);
  const hash = createHash("sha256");
  hash.update(`files\0${filenames.length}\0`);
  for (const relative of filenames) {
    const segments = validateFingerprintRelativePath(relative);
    const bytes = readExactFingerprintFile(rootSnapshot, relative, segments);
    hash.update(`${relative}\0${bytes.length}\0`);
    hash.update(bytes);
  }
  assertSameFingerprintRoot(rootSnapshot, inspectFingerprintRoot(rootSnapshot.lexicalRoot));
  return hash.digest("hex");
}

function trackedSsoExecutionFiles(repositoryRoot) {
  const source = runLocalCommand(
    "git",
    ["ls-files", "-z", "--", ...SSO_EXECUTION_PATHS],
    {
      cwd: repositoryRoot,
      environment: closedChildEnvironment(repositoryRoot),
      label: "SSO execution source lookup",
      suppressDiagnostic: true,
    },
  );
  const files = source.split("\0").filter((filename) => filename.length > 0);
  assert.deepEqual(
    files,
    [...new Set(files)].sort(),
    "SSO execution source path set is not exact and ordered",
  );
  for (const required of [
    "apps/sso/package.json",
    "apps/sso/test/global-logout.spec.ts",
    "apps/sso/test/recovery.spec.ts",
    "apps/sso/worker/global-logout.ts",
    "apps/sso/worker/recovery.ts",
    "apps/sso/wrangler.jsonc",
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
  ]) {
    assert.ok(files.includes(required), `SSO execution source lacks ${required}`);
  }
  assert.ok(
    files.some((filename) => filename.startsWith("patches/")),
    "SSO execution source lacks its package patch inputs",
  );
  return files;
}

function ssoExecutionFingerprint(identityRoot, repositoryRoot) {
  assert.equal(
    realpathSync(identityRoot),
    realpathSync(path.join(repositoryRoot, "apps", "sso")),
    "SSO execution source root differs from the repository-owned path",
  );
  const trackedFilesBefore = trackedSsoExecutionFiles(repositoryRoot);
  const fingerprint = exactFileSetFingerprint(
    repositoryRoot,
    trackedFilesBefore,
  );
  assert.deepEqual(
    trackedSsoExecutionFiles(repositoryRoot),
    trackedFilesBefore,
    "SSO execution source path set changed while it was fingerprinted",
  );
  return fingerprint;
}

function dependencyFingerprint(name, identityRoot, repositoryRoot) {
  if (name === "global_logout_0018" || name === "recovery_0019") {
    return ssoExecutionFingerprint(identityRoot, repositoryRoot);
  }
  const sqlContract = SQL_CONTRACTS[name];
  if (sqlContract) return sqlContractFingerprint(identityRoot, sqlContract);
  if (name === "release_automation") {
    return exactFileSetFingerprint(
      repositoryRoot,
      RELEASE_AUTOMATION_FINGERPRINT_FILES,
    );
  }
  assert.fail(`dependency ${name} has no executable fingerprint contract`);
}

export function validateGlobalLogoutProofReport(report) {
  assert.ok(report && typeof report === "object" && !Array.isArray(report));
  assert.equal(report.success, true);
  assert.equal(report.numTotalTestSuites, GLOBAL_LOGOUT_SUITE_COUNT);
  assert.equal(report.numPassedTestSuites, GLOBAL_LOGOUT_SUITE_COUNT);
  assert.equal(report.numFailedTestSuites, 0);
  assert.equal(report.numPendingTestSuites, 0);
  assert.equal(report.numTotalTests, GLOBAL_LOGOUT_TEST_COUNT);
  assert.equal(report.numPassedTests, GLOBAL_LOGOUT_TEST_COUNT);
  assert.equal(report.numFailedTests, 0);
  assert.equal(report.numPendingTests, 0);
  assert.equal(report.numTodoTests, 0);
  assert.ok(Array.isArray(report.testResults));
  assert.equal(report.testResults.length, 1);
  const [testResult] = report.testResults;
  assert.equal(
    path.resolve(testResult.name),
    path.join(ssoRoot, "test", "global-logout.spec.ts"),
  );
  assert.equal(testResult.status, "passed");
  assert.ok(Array.isArray(testResult.assertionResults));
  assert.equal(testResult.assertionResults.length, GLOBAL_LOGOUT_TEST_COUNT);
  assert.ok(
    testResult.assertionResults.every(
      ({ ancestorTitles, status }) =>
        status === "passed" &&
        Array.isArray(ancestorTitles) &&
        ancestorTitles.length === 1 &&
        ancestorTitles[0] === "durable global logout",
    ),
  );
  return report;
}

export function runGlobalLogoutDependencyProof(homeDirectory) {
  const contract = SQL_CONTRACTS.global_logout_0018;
  assert.equal(
    sqlContractState(ssoRoot, contract),
    "source_present_unverified",
    "global-logout source contract is invalid",
  );
  const sourceFingerprint = dependencyFingerprint(
    "global_logout_0018",
    ssoRoot,
    repoRoot,
  );
  const reportFilename = path.join(
    homeDirectory,
    `global-logout-proof-${crypto.randomUUID()}.json`,
  );
  try {
    runWorkspaceBinary(
      ssoRoot,
      "vitest",
      [
        "run",
        "test/global-logout.spec.ts",
        "--reporter=json",
        `--outputFile=${reportFilename}`,
      ],
      {
        environment: closedChildEnvironment(homeDirectory),
        label: "global-logout dependency proof",
      },
    );
    const reportSource = fileState(reportFilename);
    assert.equal(reportSource.state, "present");
    validateGlobalLogoutProofReport(JSON.parse(reportSource.text));
  } finally {
    rmSync(reportFilename, { force: true });
  }
  assert.equal(
    dependencyFingerprint("global_logout_0018", ssoRoot, repoRoot),
    sourceFingerprint,
    "global-logout execution source changed while its proof was running",
  );
  const proof = Object.freeze({});
  dependencyProofs.set(proof, {
    identityRoot: realpathSync(ssoRoot),
    name: "global_logout_0018",
    repositoryRoot: realpathSync(repoRoot),
    sourceFingerprint,
  });
  return proof;
}

export function validateRecoveryProofReport(report) {
  assert.ok(report && typeof report === "object" && !Array.isArray(report));
  assert.equal(report.success, true);
  assert.equal(report.numTotalTestSuites, RECOVERY_SUITE_COUNT);
  assert.equal(report.numPassedTestSuites, RECOVERY_SUITE_COUNT);
  assert.equal(report.numFailedTestSuites, 0);
  assert.equal(report.numPendingTestSuites, 0);
  assert.equal(report.numTotalTests, RECOVERY_TEST_COUNT);
  assert.equal(report.numPassedTests, RECOVERY_TEST_COUNT);
  assert.equal(report.numFailedTests, 0);
  assert.equal(report.numPendingTests, 0);
  assert.equal(report.numTodoTests, 0);
  assert.ok(Array.isArray(report.testResults));
  assert.equal(report.testResults.length, 1);
  const [testResult] = report.testResults;
  assert.equal(
    path.resolve(testResult.name),
    path.join(ssoRoot, "test", "recovery.spec.ts"),
  );
  assert.equal(testResult.status, "passed");
  assert.ok(Array.isArray(testResult.assertionResults));
  assert.equal(testResult.assertionResults.length, RECOVERY_TEST_COUNT);
  const ancestorCounts = Object.fromEntries(
    Object.keys(RECOVERY_ANCESTOR_COUNTS).map((name) => [name, 0]),
  );
  for (const assertion of testResult.assertionResults) {
    assert.equal(assertion.status, "passed");
    assert.ok(Array.isArray(assertion.ancestorTitles));
    assert.equal(assertion.ancestorTitles.length, 1);
    const [ancestor] = assertion.ancestorTitles;
    assert.ok(Object.hasOwn(ancestorCounts, ancestor));
    ancestorCounts[ancestor] += 1;
  }
  assert.deepEqual(ancestorCounts, RECOVERY_ANCESTOR_COUNTS);
  return report;
}

export function runRecoveryDependencyProof(homeDirectory) {
  const contract = SQL_CONTRACTS.recovery_0019;
  assert.equal(
    sqlContractState(ssoRoot, contract),
    "source_present_unverified",
    "recovery source contract is invalid",
  );
  const sourceFingerprint = dependencyFingerprint(
    "recovery_0019",
    ssoRoot,
    repoRoot,
  );
  const reportFilename = path.join(
    homeDirectory,
    `recovery-proof-${crypto.randomUUID()}.json`,
  );
  try {
    runWorkspaceBinary(
      ssoRoot,
      "vitest",
      [
        "run",
        "test/recovery.spec.ts",
        "--reporter=json",
        `--outputFile=${reportFilename}`,
      ],
      {
        environment: closedChildEnvironment(homeDirectory),
        label: "recovery dependency proof",
      },
    );
    const reportSource = fileState(reportFilename);
    assert.equal(reportSource.state, "present");
    validateRecoveryProofReport(JSON.parse(reportSource.text));
  } finally {
    rmSync(reportFilename, { force: true });
  }
  assert.equal(
    dependencyFingerprint("recovery_0019", ssoRoot, repoRoot),
    sourceFingerprint,
    "recovery execution source changed while its proof was running",
  );
  const proof = Object.freeze({});
  dependencyProofs.set(proof, {
    identityRoot: realpathSync(ssoRoot),
    name: "recovery_0019",
    repositoryRoot: realpathSync(repoRoot),
    sourceFingerprint,
  });
  return proof;
}

function exactTestCounts(value, count) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(value, {
    tests: count,
    failed: 0,
    passed: count,
    cancelled: 0,
    skipped: 0,
    todo: 0,
    topLevel: count,
    suites: 0,
  });
}

export function validateReleaseAutomationProofEvents(source) {
  assert.equal(typeof source, "string");
  const lines = source.split("\n").filter((line) => line.length > 0);
  const events = lines.map((line) => JSON.parse(line));
  assert.ok(
    events.every(({ type }) => ["test:pass", "test:fail", "test:summary"].includes(type)),
  );
  assert.equal(events.some(({ type }) => type === "test:fail"), false);
  const passes = events.filter(({ type }) => type === "test:pass");
  const summaries = events.filter(({ type }) => type === "test:summary");
  assert.equal(passes.length, RELEASE_TEST_COUNT);
  assert.equal(summaries.length, RELEASE_SECURITY_TESTS.length + 1);

  const passCounts = new Map();
  for (const event of passes) {
    assert.equal(event.data.nesting, 0);
    assert.equal(event.data.details?.type, "test");
    assert.equal(typeof event.data.name, "string");
    assert.ok(event.data.name.length > 0);
    const relative = path.relative(repoRoot, path.resolve(event.data.file));
    assert.ok(!relative.startsWith(".."));
    passCounts.set(relative, (passCounts.get(relative) ?? 0) + 1);
  }

  for (const contract of RELEASE_SECURITY_TESTS) {
    const relative = path.join("scripts", "security", contract.filename);
    assert.equal(passCounts.get(relative), contract.count, relative);
    const summary = summaries.find(
      ({ data }) =>
        data.file && path.resolve(data.file) === path.join(repoRoot, relative),
    );
    assert.ok(summary, `${relative} lacks an exact summary`);
    assert.equal(summary.data.success, true);
    exactTestCounts(summary.data.counts, contract.count);
  }
  assert.deepEqual(
    [...passCounts.keys()].sort(),
    RELEASE_SECURITY_TESTS.map(({ filename }) =>
      path.join("scripts", "security", filename),
    ).sort(),
  );
  const aggregate = summaries.filter(({ data }) => data.file === undefined);
  assert.equal(aggregate.length, 1);
  assert.equal(aggregate[0].data.success, true);
  exactTestCounts(aggregate[0].data.counts, RELEASE_TEST_COUNT);
  return events;
}

export function runReleaseAutomationDependencyProof(homeDirectory) {
  assert.equal(
    releaseContractState(repoRoot),
    "source_present_unverified",
    "release-automation source contract is invalid",
  );
  assert.deepEqual(
    readdirSync(path.join(repoRoot, "scripts", "security"))
      .filter((filename) => filename.endsWith(".test.mjs"))
      .sort(),
    RELEASE_SECURITY_TESTS.map(({ filename }) => filename).sort(),
    "release-automation security test file set drifted",
  );
  const sourceFingerprint = dependencyFingerprint(
    "release_automation",
    ssoRoot,
    repoRoot,
  );
  const output = runLocalCommand(
    process.execPath,
    [
      "--test",
      "--test-concurrency=1",
      `--test-reporter=${path.join(repoRoot, "scripts", "public-readiness", "exact-test-reporter.mjs")}`,
      ...RELEASE_SECURITY_TESTS.map(({ filename }) =>
        path.join("scripts", "security", filename),
      ),
    ],
    {
      cwd: repoRoot,
      environment: closedChildEnvironment(homeDirectory),
      label: "release-automation dependency proof",
    },
  );
  validateReleaseAutomationProofEvents(output);
  assert.equal(
    dependencyFingerprint("release_automation", ssoRoot, repoRoot),
    sourceFingerprint,
    "release-automation source changed while its proof was running",
  );
  const proof = Object.freeze({});
  dependencyProofs.set(proof, {
    identityRoot: realpathSync(ssoRoot),
    name: "release_automation",
    repositoryRoot: realpathSync(repoRoot),
    sourceFingerprint,
  });
  return proof;
}

function hasExportModifier(statement) {
  return Boolean(
    statement.modifiers?.some(
      (modifier) => modifier.kind === SyntaxKind.ExportKeyword,
    ),
  );
}

function moduleExports(filename) {
  const source = fileState(filename);
  if (source.state !== "present") return source;
  const suffix = path.extname(filename).toLowerCase() || ".ts";
  const virtualFilename = `/pgid-dependency-contract-${parsedSourceSequence++}${suffix}`;
  if (previousParsedSource) virtualFileSystem.removeFile(previousParsedSource);
  virtualFileSystem.writeFile(virtualFilename, source.text);
  const snapshot = compiler.updateSnapshot({
    closeFiles: previousParsedSource ? [previousParsedSource] : undefined,
    fileChanges: {
      created: [virtualFilename],
      deleted: previousParsedSource ? [previousParsedSource] : undefined,
    },
    openFiles: [virtualFilename],
  });
  previousParsedSource = virtualFilename;
  try {
    const project = snapshot.getDefaultProjectForFile(virtualFilename);
    const sourceFile = project?.program.getSourceFile(virtualFilename);
    if (
      !project ||
      !sourceFile ||
      project.program.getSyntacticDiagnostics(virtualFilename).length > 0
    ) {
      return { state: "invalid" };
    }
    const functions = new Set();
    const strings = new Map();
    for (const statement of sourceFile.statements) {
      if (!hasExportModifier(statement)) continue;
      if (statement.kind === SyntaxKind.FunctionDeclaration && statement.name) {
        functions.add(statement.name.text);
      }
      if (statement.kind === SyntaxKind.VariableStatement) {
        for (const declaration of statement.declarationList.declarations) {
          if (
            declaration.name?.kind === SyntaxKind.Identifier &&
            declaration.initializer?.kind === SyntaxKind.StringLiteral
          ) {
            strings.set(declaration.name.text, declaration.initializer.text);
          }
        }
      }
    }
    return { functions, state: "present", strings };
  } finally {
    snapshot.dispose();
  }
}

function parseJsonc(filename) {
  const source = fileState(filename);
  if (source.state !== "present") return source;
  const errors = [];
  const value = parseJsoncText(source.text, errors, {
    allowTrailingComma: true,
    disallowComments: false,
  });
  return errors.length > 0 || !value || typeof value !== "object"
    ? { state: "invalid" }
    : { state: "present", value };
}

function archiveContractState(identityRoot) {
  const moduleFilename = path.join(identityRoot, "worker", "audit-archive.ts");
  const configFilename = path.join(identityRoot, "wrangler.jsonc");
  const source = allFilesPresent([moduleFilename, configFilename]);
  if (source.state !== "present") return source.state;
  const module = moduleExports(moduleFilename);
  const config = parseJsonc(configFilename);
  if (module.state !== "present" || config.state !== "present") {
    return "source_invalid";
  }
  const contract = module.strings.get("PUBLIC_READINESS_ARCHIVE_CONTRACT");
  const bucket = Array.isArray(config.value.r2_buckets)
    ? config.value.r2_buckets.find(
        (entry) =>
          entry &&
          typeof entry === "object" &&
          entry.binding === "AUDIT_ARCHIVE" &&
          typeof entry.bucket_name === "string" &&
          entry.bucket_name.length > 0 &&
          entry.remote !== true,
      )
    : undefined;
  return contract === "pgid-audit-archive-v1" &&
    module.functions.has("archiveAuditBatch") &&
    module.functions.has("restoreAuditArchive") &&
    bucket
    ? "source_present_unverified"
    : "source_invalid";
}

function releasePolicyValid(value) {
  const production = value?.environments?.production;
  const testRp = value?.environments?.localTestRp;
  return (
    value?.schemaVersion === 2 &&
    value?.artifact?.entrypoint === "index.js" &&
    value?.staticAssets?.entrypoint === "index.html" &&
    production?.sourceConfig === "apps/sso/wrangler.jsonc" &&
    production?.worker?.name === "pg72-id" &&
    testRp?.sourceConfig === "apps/test-rp/wrangler.jsonc"
  );
}

function releaseContractState(repositoryRoot) {
  const policyFilename = path.join(
    repositoryRoot,
    "security",
    "release-policy.json",
  );
  const dastFilename = path.join(
    repositoryRoot,
    "scripts",
    "security",
    "dast.mjs",
  );
  const source = allFilesPresent([policyFilename, dastFilename]);
  if (source.state !== "present") return source.state;
  let policy;
  try {
    policy = JSON.parse(source.files[0].text);
  } catch {
    return "source_invalid";
  }
  const module = moduleExports(dastFilename);
  if (module.state !== "present") return "source_invalid";
  return releasePolicyValid(policy) &&
    module.functions.has("authorizeDastTarget") &&
    module.functions.has("scanPgid") &&
    module.functions.has("scanLocalRp")
    ? "source_present_unverified"
    : "source_invalid";
}

function sourceStatuses(identityRoot, repositoryRoot) {
  return new Map([
    ...Object.entries(SQL_CONTRACTS).map(([name, contract]) => [
      name,
      sqlContractState(identityRoot, contract),
    ]),
    ["encrypted_r2_archive", archiveContractState(identityRoot)],
    ["release_automation", releaseContractState(repositoryRoot)],
  ]);
}

export function dependencyStatus(options = {}) {
  assert.ok(options && typeof options === "object" && !Array.isArray(options));
  const allowedOptions = ["identityRoot", "proofs", "repositoryRoot"];
  assert.deepEqual(
    Object.keys(options).filter((name) => !allowedOptions.includes(name)),
    [],
    "dependency status received an unapproved option",
  );
  const {
    identityRoot = ssoRoot,
    repositoryRoot = repoRoot,
    proofs = [],
  } = options;
  assert.ok(Array.isArray(proofs), "dependency proofs must be an array");
  const verifiedNames = new Set();
  for (const proof of proofs) {
    const evidence =
      proof && typeof proof === "object" ? dependencyProofs.get(proof) : undefined;
    assert.ok(evidence, "dependency proof was not produced by an executed check");
    assert.equal(evidence.identityRoot, realpathSync(identityRoot));
    assert.equal(evidence.repositoryRoot, realpathSync(repositoryRoot));
    assert.equal(
      evidence.sourceFingerprint,
      dependencyFingerprint(evidence.name, identityRoot, repositoryRoot),
      "dependency source no longer matches its executed proof",
    );
    assert.equal(verifiedNames.has(evidence.name), false, "dependency proof is duplicated");
    verifiedNames.add(evidence.name);
  }
  const source = sourceStatuses(identityRoot, repositoryRoot);
  return REQUIRED_DEPENDENCY_NAMES.map((name) => {
    const sourceStatus = source.get(name);
    assert.ok(DEPENDENCY_STATUSES.includes(sourceStatus));
    return {
      name,
      status:
        sourceStatus === "source_present_unverified" && verifiedNames.has(name)
          ? "verified"
          : sourceStatus,
    };
  });
}
