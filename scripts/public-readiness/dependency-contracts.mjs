import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import {
  existsSync,
  lstatSync,
  readFileSync,
  realpathSync,
  rmSync,
} from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parse as parseJsoncText } from "jsonc-parser";

import {
  closedChildEnvironment,
  repoRoot,
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
    assert.equal(
      evidence.sourceFingerprint,
      sqlContractFingerprint(identityRoot, SQL_CONTRACTS[evidence.name]),
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
