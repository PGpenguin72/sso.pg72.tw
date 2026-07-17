import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
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
      /create table\s+"alert_state"/i,
      /create table\s+"alert_outbox"/i,
      /create index\s+"alert_outbox_due_idx"/i,
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

function exactFileSetFingerprint(root, filenames) {
  const hash = createHash("sha256");
  for (const relative of filenames) {
    const filename = path.join(root, relative);
    const stat = lstatSync(filename);
    assert.ok(stat.isFile() && !stat.isSymbolicLink(), `${relative} is not an exact regular file`);
    const bytes = readFileSync(filename);
    hash.update(`${relative}\0${bytes.length}\0`);
    hash.update(bytes);
  }
  return hash.digest("hex");
}

function dependencyFingerprint(name, identityRoot, repositoryRoot) {
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
  const sourceFingerprint = sqlContractFingerprint(ssoRoot, contract);
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
    sqlContractFingerprint(ssoRoot, contract),
    sourceFingerprint,
    "global-logout source changed while its proof was running",
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
  const sourceFingerprint = sqlContractFingerprint(ssoRoot, contract);
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
    sqlContractFingerprint(ssoRoot, contract),
    sourceFingerprint,
    "recovery source changed while its proof was running",
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
