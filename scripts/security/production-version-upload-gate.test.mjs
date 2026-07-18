import assert from "node:assert/strict";
import {
  appendFileSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PINNED_WRANGLER,
  PRODUCTION_EXECUTION_BLOCKERS,
  PRODUCTION_WORKER_NAME,
  ProductionUploadGateError,
  UPLOAD_MESSAGE_PREFIX,
  WRANGLER_OUTPUT_MAX_BYTES,
  buildWranglerChildEnvironment,
  canonicalJson,
  classifyPostflight,
  createFailClosedRemoteAdapter,
  derivePrivateProductionConfig,
  evaluateOfflineProductionVersionUploadEvidence,
  expectedGeneratedProductionConfig,
  normalizePrivateProductionConfig,
  parseWranglerOutputJsonl,
  runProductionVersionUploadGate,
  sha256,
  validateNormalizedSnapshot,
  validateLocalReleaseContext,
  validateProductionEnvironment,
  verifyUploadedVersion,
  withPrivateProductionUploadWorkspace,
  wranglerUploadArguments,
} from "./production-version-upload-gate.mjs";

const CANDIDATE = "a".repeat(40);
const TREE = "b".repeat(40);
const ACCOUNT_ID = "c".repeat(32);
const D1_UUID = "11111111-1111-1111-1111-111111111111";
const ACTIVE_VERSION = "33333333-3333-4333-8333-333333333333";
const NEW_VERSION = "22222222-2222-4222-8222-222222222222";
const SERVICE_TAG = "service-tag-fixture";
const NOW = Date.parse("2026-07-19T00:00:00.000Z");
const BUILD_UUID = "55555555-5555-4555-8555-555555555555";
const RELEASE_POLICY = JSON.parse(
  readFileSync(new URL("../../security/release-policy.json", import.meta.url), "utf8"),
);

function generatedConfig(root) {
  return expectedGeneratedProductionConfig(RELEASE_POLICY, root);
}

function expectCode(action, code) {
  assert.throws(
    action,
    (error) =>
      error instanceof ProductionUploadGateError && error.code === code,
  );
}

async function expectCodeAsync(action, code) {
  await assert.rejects(
    action,
    (error) =>
      error instanceof ProductionUploadGateError && error.code === code,
  );
}

function environment(overrides = {}) {
  return {
    CI: "true",
    WORKERS_CI: "1",
    WORKERS_CI_BRANCH: "main",
    WORKERS_CI_BUILD_UUID: BUILD_UUID,
    WORKERS_CI_COMMIT_SHA: CANDIDATE,
    CLOUDFLARE_API_TOKEN: String(CANDIDATE.length),
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    PGID_PRODUCTION_ACCOUNT_ID: ACCOUNT_ID,
    PGID_PRODUCTION_D1_DATABASE_ID: D1_UUID,
    WRANGLER_CI_OVERRIDE_NAME: PRODUCTION_WORKER_NAME,
    WRANGLER_CI_MATCH_TAG: SERVICE_TAG,
    ...overrides,
  };
}

function runtimeBindings(config, secretNames = config.secrets.required) {
  const bindings = [];
  for (const [name, text] of Object.entries(config.vars)) {
    bindings.push({ name, text: String(text), type: "plain_text" });
  }
  for (const database of config.d1_databases) {
    bindings.push({
      database_id: database.database_id,
      name: database.binding,
      type: "d1",
    });
  }
  for (const queue of config.queues.producers) {
    bindings.push({ name: queue.binding, queue_name: queue.queue, type: "queue" });
  }
  for (const rateLimit of config.ratelimits) {
    bindings.push({
      name: rateLimit.name,
      namespace_id: rateLimit.namespace_id,
      simple: {
        limit: rateLimit.simple.limit,
        period: rateLimit.simple.period,
      },
      type: "ratelimit",
    });
  }
  bindings.push({ name: config.assets.binding, type: "assets" });
  for (const name of secretNames) bindings.push({ name, type: "secret_text" });
  return bindings;
}

function versionDetail(
  id,
  config,
  {
    tag = "old",
    message = "old",
    secretNames = config.secrets.required,
  } = {},
) {
  return {
    annotations: {
      "workers/message": message,
      "workers/tag": tag,
    },
    id,
    metadata: { hasPreview: false },
    resources: {
      bindings: runtimeBindings(config, secretNames),
      script_runtime: {
        compatibility_date: config.compatibility_date,
        compatibility_flags: [...config.compatibility_flags],
      },
    },
  };
}

function normalizedSnapshot(config, { uploaded = false } = {}) {
  return {
    activeVersion: versionDetail(ACTIVE_VERSION, config),
    deployments: [
      {
        id: "44444444-4444-4444-8444-444444444444",
        versions: [{ percentage: 100, version_id: ACTIVE_VERSION }],
      },
    ],
    latestVersion: uploaded
      ? versionDetail(NEW_VERSION, config, {
          tag: CANDIDATE,
          message: `${UPLOAD_MESSAGE_PREFIX}${CANDIDATE}`,
        })
      : versionDetail(ACTIVE_VERSION, config),
    schemaVersion: 1,
    scriptSettings: {
      logpush: false,
      observability: { enabled: true },
      tags: ["production"],
      tail_consumers: [],
    },
    serviceTag: SERVICE_TAG,
    singleWriter: true,
    subdomain: { enabled: false, previews_enabled: false },
    versions: uploaded
      ? [{ id: NEW_VERSION }, { id: ACTIVE_VERSION }]
      : [{ id: ACTIVE_VERSION }],
    workerName: PRODUCTION_WORKER_NAME,
  };
}

function makeFixture(context) {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), "pgid-upload-gate-test-")));
  context.after(() => rmSync(root, { force: true, recursive: true }));
  const generated = generatedConfig(root);
  const generatedPath = path.join(root, "apps/sso/dist/pg72_id/wrangler.json");
  mkdirSync(path.dirname(generatedPath), { recursive: true });
  writeFileSync(generatedPath, `${JSON.stringify(generated, null, 2)}\n`);
  const policyPath = path.join(root, "security/release-policy.json");
  mkdirSync(path.dirname(policyPath), { recursive: true });
  writeFileSync(policyPath, `${JSON.stringify(RELEASE_POLICY, null, 2)}\n`);

  const wranglerRoot = path.join(root, "apps/sso/node_modules/wrangler");
  mkdirSync(path.join(wranglerRoot, "wrangler-dist"), { recursive: true });
  mkdirSync(path.join(wranglerRoot, "bin"), { recursive: true });
  const contents = {
    package: Buffer.from('{"version":"4.110.0"}\n'),
    cli: Buffer.from("// reviewed wrangler cli fixture\n"),
    launcher: Buffer.from("// reviewed launcher fixture\n"),
  };
  const wranglerPaths = {
    packageRoot: wranglerRoot,
    package: path.join(wranglerRoot, "package.json"),
    cli: path.join(wranglerRoot, "wrangler-dist/cli.js"),
    launcher: path.join(wranglerRoot, "bin/wrangler.js"),
  };
  writeFileSync(wranglerPaths.package, contents.package);
  writeFileSync(wranglerPaths.cli, contents.cli);
  writeFileSync(wranglerPaths.launcher, contents.launcher);
  const expectedWranglerDigests = Object.fromEntries(
    Object.entries(contents).map(([key, bytes]) => [key, sha256(bytes)]),
  );
  const tempBase = path.join(root, "private-temp");
  mkdirSync(tempBase);
  return {
    root,
    generated,
    generatedPath,
    wranglerPaths,
    expectedWranglerDigests,
    tempBase,
  };
}

function localHarness(context, overrides = {}) {
  const fixture = makeFixture(context);
  let gitCalls = 0;
  const runProcess = async (command, args, options) => {
    assert.equal(command, "git");
    assert.equal(options.cwd, fixture.root);
    gitCalls += 1;
    const joined = args.join(" ");
    if (joined === "rev-parse HEAD^{commit}") {
      return processResult(`${CANDIDATE}\n`);
    }
    if (joined === "rev-parse HEAD^{tree}") return processResult(`${TREE}\n`);
    if (joined === "status --porcelain=v1 --untracked-files=all") {
      return processResult(overrides.gitStatus ?? "");
    }
    assert.fail(`unexpected git command: ${joined}`);
  };
  const deps = {
    fs: importFs,
    randomBytes: () => Buffer.alloc(16, 7),
    runProcess,
    nodeVersion: "24.0.0",
    execArgv: [],
    tmpdir: () => `${fixture.tempBase}${path.sep}`,
  };
  return {
    fixture,
    deps,
    get gitCalls() {
      return gitCalls;
    },
  };
}

import * as importFs from "node:fs";

function processResult(stdout, overrides = {}) {
  return {
    status: 0,
    signal: null,
    timedOut: false,
    overflow: false,
    stdout: Buffer.from(stdout),
    stderr: Buffer.alloc(0),
    ...overrides,
  };
}

function normalizedChildResult(overrides = {}) {
  return {
    status: 0,
    signal: null,
    timedOut: false,
    overflow: false,
    ...overrides,
  };
}

function outputRecord(overrides = {}) {
  return {
    type: "version-upload",
    version: 1,
    worker_name: PRODUCTION_WORKER_NAME,
    worker_tag: SERVICE_TAG,
    version_id: NEW_VERSION,
    worker_name_overridden: false,
    timestamp: new Date(NOW).toISOString(),
    ...overrides,
  };
}

async function validateHarness(harness, options = {}) {
  return await validateLocalReleaseContext({
    repositoryRoot: harness.fixture.root,
    environment: environment(options.environment),
    deps: harness.deps,
    wranglerPaths: harness.fixture.wranglerPaths,
    expectedWranglerDigests: harness.fixture.expectedWranglerDigests,
  });
}

test("production entry is structurally blocked before any injected action", async () => {
  let calls = 0;
  await expectCodeAsync(
    () =>
      runProductionVersionUploadGate({
        deps: { runProcess: () => (calls += 1) },
        remote: { readSnapshot: () => (calls += 1) },
      }),
    "PRODUCTION_EXECUTION_REVIEW_REQUIRED",
  );
  assert.equal(calls, 0);
  assert.deepEqual(PRODUCTION_EXECUTION_BLOCKERS, [
    "external-c-normalized-api-adapter-review",
    "owner-workers-builds-trigger-and-token-custody",
    "pinned-wrangler-retry-disable-or-nonretrying-upload-adapter-review",
    "child-process-tree-custody-review",
    "sealed-wrangler-executable-dependency-closure",
    "trusted-git-binary-and-config-custody",
  ]);
});

test("validates local identity using only injected offline dependencies", async (context) => {
  const harness = localHarness(context);
  const result = await validateHarness(harness);
  assert.equal(result.head, CANDIDATE);
  assert.equal(result.tree, TREE);
  assert.equal(result.buildCorrelationSha256, sha256(BUILD_UUID));
  assert.equal(result.wranglerCliPath, realpathSync(harness.fixture.wranglerPaths.cli));
  assert.equal(harness.gitCalls, 3);
});

test("normalization permits exactly the four reviewed private deltas", () => {
  const root = "/reviewed/repository";
  const generated = generatedConfig(root);
  const context = { accountId: ACCOUNT_ID, d1Uuid: D1_UUID };
  const privateConfig = derivePrivateProductionConfig(generated, context);
  assert.deepEqual(normalizePrivateProductionConfig(privateConfig, context), generated);
  for (const mutate of [
    (value) => (value.account_id = "d".repeat(32)),
    (value) => (value.workers_dev = true),
    (value) => (value.preview_urls = true),
    (value) => (value.d1_databases[0].database_id = ACTIVE_VERSION),
  ]) {
    const changed = structuredClone(privateConfig);
    mutate(changed);
    assert.throws(() => normalizePrivateProductionConfig(changed, context));
  }
  const extra = structuredClone(privateConfig);
  extra.unreviewed = true;
  assert.notDeepEqual(normalizePrivateProductionConfig(extra, context), generated);
});

test("rejects branch, SHA, account, worker, tag, GitHub Actions, and override inputs", () => {
  const cases = [
    ["CI_BRANCH", { WORKERS_CI_BRANCH: "preview" }],
    ["CI_BUILD_UUID", { WORKERS_CI_BUILD_UUID: "not-a-uuid" }],
    ["CI_SHA", { WORKERS_CI_COMMIT_SHA: "not-a-sha" }],
    [
      "API_TOKEN_MISSING",
      {
        CLOUDFLARE_API_TOKEN: Buffer.from([
          98, 97, 100, 10, 116, 111, 107, 101, 110,
        ]).toString(),
      },
    ],
    ["ACCOUNT_ID_MISMATCH", { PGID_PRODUCTION_ACCOUNT_ID: "d".repeat(32) }],
    ["WORKER_NAME_MISMATCH", { WRANGLER_CI_OVERRIDE_NAME: "other" }],
    ["MATCH_TAG_INVALID", { WRANGLER_CI_MATCH_TAG: "" }],
    ["GITHUB_ACTIONS_FORBIDDEN", { GITHUB_ACTIONS: "true" }],
    ["FORBIDDEN_ENVIRONMENT", { NODE_OPTIONS: "--require=other" }],
    ["FORBIDDEN_ENVIRONMENT", { NODE_PATH: "/unreviewed" }],
    ["FORBIDDEN_ENVIRONMENT", { LD_PRELOAD: "/unreviewed.so" }],
    ["FORBIDDEN_ENVIRONMENT", { DYLD_INSERT_LIBRARIES: "/unreviewed.dylib" }],
    ["FORBIDDEN_ENVIRONMENT", { CF_API_TOKEN: String(CANDIDATE.length) }],
    ["FORBIDDEN_ENVIRONMENT", { CLOUDFLARE_ENV: "staging" }],
    ["FORBIDDEN_ENVIRONMENT", { WRANGLER_API_BASE_URL: "https://example.invalid" }],
    ["FORBIDDEN_ENVIRONMENT", { WRANGLER_CI_GENERATE_PREVIEW_ALIAS: "false" }],
    ["FORBIDDEN_ENVIRONMENT", { WORKERS_CI_UNREVIEWED: "1" }],
    ["FORBIDDEN_ENVIRONMENT", { HTTPS_PROXY: "http://example.invalid" }],
  ];
  for (const [code, override] of cases) {
    expectCode(() => validateProductionEnvironment(environment(override)), code);
  }
});

test("rejects inherited Node exec arguments before running git", async (context) => {
  const harness = localHarness(context);
  harness.deps.execArgv = ["--require=/unreviewed.cjs"];
  await expectCodeAsync(() => validateHarness(harness), "NODE_EXEC_ARGV_FORBIDDEN");
  assert.equal(harness.gitCalls, 0);
});

test("finishes all local identity checks before invoking a remote adapter", async (context) => {
  const harness = localHarness(context, { gitStatus: "?? unreviewed\n" });
  await expectCodeAsync(() => validateHarness(harness), "GIT_DIRTY");
  assert.equal(harness.gitCalls, 3);
});

test("requires exact remote state while separating latest from active version", () => {
  const config = derivePrivateProductionConfig(generatedConfig("/reviewed"), {
    accountId: ACCOUNT_ID,
    d1Uuid: D1_UUID,
  });
  const valid = normalizedSnapshot(config);
  assert.doesNotThrow(() =>
    validateNormalizedSnapshot(valid, { matchTag: SERVICE_TAG }),
  );
  for (const [code, mutate] of [
    ["REMOTE_PREVIEW_STATE", (value) => (value.subdomain.enabled = true)],
    ["REMOTE_PREVIEW_STATE", (value) => delete value.subdomain.previews_enabled],
    ["REMOTE_TAG_STATE", (value) => value.scriptSettings.tags.push("cf:service=legacy")],
    ["REMOTE_SINGLE_WRITER_EVIDENCE_REQUIRED", (value) => (value.singleWriter = false)],
    ["REMOTE_LATEST_VERSION_MISMATCH", (value) => value.versions.unshift({ id: NEW_VERSION })],
  ]) {
    const changed = structuredClone(valid);
    mutate(changed);
    expectCode(
      () => validateNormalizedSnapshot(changed, { matchTag: SERVICE_TAG }),
      code,
    );
  }
  const inactiveLatest = normalizedSnapshot(config);
  inactiveLatest.versions.unshift({ id: NEW_VERSION });
  inactiveLatest.latestVersion = versionDetail(NEW_VERSION, config);
  assert.doesNotThrow(() =>
    validateNormalizedSnapshot(inactiveLatest, { matchTag: SERVICE_TAG }),
  );
});

test("parses exactly one bounded JSONL record without preview fields", () => {
  const base = {
    type: "version-upload",
    version: 1,
    worker_name: PRODUCTION_WORKER_NAME,
    worker_tag: SERVICE_TAG,
    version_id: NEW_VERSION,
    worker_name_overridden: false,
    timestamp: new Date(NOW).toISOString(),
  };
  const parse = (value, window = {}) =>
    parseWranglerOutputJsonl(Buffer.from(`${JSON.stringify(value)}\n`), {
      matchTag: SERVICE_TAG,
      startedAt: NOW,
      finishedAt: NOW,
      ...window,
    });
  assert.deepEqual(parse(base), base);
  for (const [code, value] of [
    ["WRANGLER_OUTPUT_SCHEMA", { ...base, preview_url: null }],
    ["WRANGLER_OUTPUT_SCHEMA", { ...base, preview_alias_url: null }],
    ["WRANGLER_OUTPUT_IDENTITY", { ...base, worker_name_overridden: true }],
    ["WRANGLER_OUTPUT_IDENTITY", { ...base, version_id: ACTIVE_VERSION.slice(1) }],
    ["WRANGLER_OUTPUT_TIMESTAMP", { ...base, timestamp: new Date(NOW - 1).toISOString() }],
  ]) {
    expectCode(() => parse(value), code);
  }
  expectCode(
    () =>
      parseWranglerOutputJsonl(
        Buffer.from(`${JSON.stringify(base)}\n${JSON.stringify(base)}\n`),
        { matchTag: SERVICE_TAG, startedAt: NOW, finishedAt: NOW },
      ),
    "WRANGLER_OUTPUT_LINES",
  );
  expectCode(
    () =>
      parseWranglerOutputJsonl(Buffer.alloc(WRANGLER_OUTPUT_MAX_BYTES + 1), {
        matchTag: SERVICE_TAG,
        startedAt: NOW,
        finishedAt: NOW,
      }),
    "WRANGLER_OUTPUT_SIZE",
  );
});

test("classifies only one new version with unchanged control-plane state", () => {
  const config = derivePrivateProductionConfig(generatedConfig("/reviewed"), {
    accountId: ACCOUNT_ID,
    d1Uuid: D1_UUID,
  });
  const before = normalizedSnapshot(config);
  const after = normalizedSnapshot(config, { uploaded: true });
  const outputRecord = { version_id: NEW_VERSION };
  const success = normalizedChildResult();
  assert.equal(
    classifyPostflight({ before, after, outputRecord, childResult: success }),
    NEW_VERSION,
  );
  for (const [code, mutate] of [
    ["UNEXPECTED_SUBDOMAIN_OR_IDENTITY_MUTATION", (value) => (value.subdomain.enabled = true)],
    ["UNEXPECTED_SCRIPT_SETTINGS_MUTATION", (value) => value.scriptSettings.tags.push("drift")],
    ["UNEXPECTED_ACTIVE_DEPLOYMENT_MUTATION", (value) => (value.deployments[0].id = NEW_VERSION)],
    ["MULTIPLE_OR_FOREIGN_VERSION_MUTATION", (value) => value.versions.unshift({ id: "55555555-5555-4555-8555-555555555555" })],
  ]) {
    const changed = structuredClone(after);
    mutate(changed);
    expectCode(
      () => classifyPostflight({ before, after: changed, outputRecord, childResult: success }),
      code,
    );
  }
  const staleLatestOrder = structuredClone(after);
  staleLatestOrder.versions = [
    { id: ACTIVE_VERSION },
    { id: NEW_VERSION },
  ];
  expectCode(
    () =>
      classifyPostflight({
        before,
        after: staleLatestOrder,
        outputRecord,
        childResult: success,
      }),
    "EXPECTED_VERSION_NOT_LATEST",
  );
  expectCode(
    () =>
      classifyPostflight({
        before,
        after,
        outputRecord: null,
        childResult: normalizedChildResult({ status: 1 }),
      }),
    "UNKNOWN_OUTCOME_VERSION_CREATED",
  );
  expectCode(
    () =>
      classifyPostflight({
        before,
        after: before,
        outputRecord: null,
        childResult: normalizedChildResult({ status: 1 }),
      }),
    "UNKNOWN_OUTCOME_NO_VERSION",
  );
  expectCode(
    () =>
      classifyPostflight({
        before,
        after,
        outputRecord,
        childResult: normalizedChildResult({ overflow: true }),
      }),
    "UNKNOWN_OUTCOME_VERSION_CREATED",
  );
  expectCode(
    () =>
      classifyPostflight({
        before,
        after,
        outputRecord,
        childResult: { ...normalizedChildResult(), stdout: "unreviewed" },
      }),
    "CHILD_RESULT_SCHEMA",
  );
});

test("fails closed on unreviewed version annotations, preview, secrets, and binding schemas", () => {
  const generated = generatedConfig("/reviewed");
  const privateConfig = derivePrivateProductionConfig(generated, {
    accountId: ACCOUNT_ID,
    d1Uuid: D1_UUID,
  });
  const latest = versionDetail(ACTIVE_VERSION, privateConfig);
  const valid = versionDetail(NEW_VERSION, privateConfig, {
    tag: CANDIDATE,
    message: `${UPLOAD_MESSAGE_PREFIX}${CANDIDATE}`,
  });
  assert.ok(
    verifyUploadedVersion({
      detail: valid,
      versionId: NEW_VERSION,
      candidateSha: CANDIDATE,
      message: `${UPLOAD_MESSAGE_PREFIX}${CANDIDATE}`,
      privateConfig,
      latestVersion: latest,
    }).length > 0,
  );
  const latestWithExtraSecret = versionDetail(ACTIVE_VERSION, privateConfig, {
    secretNames: [...privateConfig.secrets.required, "UNREVIEWED_SECRET"],
  });
  expectCode(
    () =>
      verifyUploadedVersion({
        detail: valid,
        versionId: NEW_VERSION,
        candidateSha: CANDIDATE,
        message: `${UPLOAD_MESSAGE_PREFIX}${CANDIDATE}`,
        privateConfig,
        latestVersion: latestWithExtraSecret,
      }),
    "RUNTIME_SECRET_INVENTORY_MISMATCH",
  );
  for (const [code, mutate] of [
    ["REMOTE_RUNTIME_SCHEMA_REVIEW_REQUIRED", (value) => delete value.annotations],
    ["REMOTE_VERSION_PREVIEW_SCHEMA_REVIEW_REQUIRED", (value) => (value.metadata.hasPreview = true)],
    ["REMOTE_SECRET_REDACTION_SCHEMA_REVIEW_REQUIRED", (value) => (value.resources.bindings.find(({ type }) => type === "secret_text").text = "redacted")],
    ["REMOTE_BINDING_TYPE_UNREVIEWED", (value) => value.resources.bindings.push({ name: "X", type: "unknown" })],
    ["REMOTE_BINDING_SCHEMA_REVIEW_REQUIRED", (value) => (value.resources.bindings.find(({ type }) => type === "d1").id = D1_UUID)],
    ["REMOTE_BINDING_DUPLICATE", (value) => value.resources.bindings.push({ name: "PG72_ID_DB", type: "assets" })],
  ]) {
    const changed = structuredClone(valid);
    mutate(changed);
    expectCode(
      () =>
        verifyUploadedVersion({
          detail: changed,
          versionId: NEW_VERSION,
          candidateSha: CANDIDATE,
          message: `${UPLOAD_MESSAGE_PREFIX}${CANDIDATE}`,
          privateConfig,
          latestVersion: latest,
        }),
      code,
    );
  }
});

test("uses only the pinned CLI path and a fixed argument surface", () => {
  const cliPath = "/reviewed/wrangler-dist/cli.js";
  const privateConfigPath = "/private/config.json";
  const value = wranglerUploadArguments({
    cliPath,
    privateConfigPath,
    candidateSha: CANDIDATE,
  });
  assert.deepEqual(value.args, [
    "--no-warnings",
    cliPath,
    "versions",
    "upload",
    "--config",
    privateConfigPath,
    "--strict",
    "--tag",
    CANDIDATE,
    "--message",
    `${UPLOAD_MESSAGE_PREFIX}${CANDIDATE}`,
  ]);
  assert.equal(value.args.some((entry) => entry.includes("bin/wrangler")), false);
  assert.equal(value.args.includes("deploy"), false);
  assert.equal(value.args.includes("--preview-alias"), false);
  assert.equal(value.args.includes("--keep-vars"), false);
  assert.equal(value.args.includes("--secrets-file"), false);
  expectCode(
    () =>
      wranglerUploadArguments({
        cliPath,
        privateConfigPath,
        candidateSha: "not-a-sha",
      }),
    "UPLOAD_ARGUMENT_CONTRACT",
  );
  expectCode(
    () =>
      wranglerUploadArguments({
        cliPath,
        privateConfigPath,
        candidateSha: { toString: () => CANDIDATE },
      }),
    "UPLOAD_ARGUMENT_CONTRACT",
  );
  for (const filename of [
    new URL("../../package.json", import.meta.url),
    new URL("../../.github/workflows/ci.yml", import.meta.url),
    new URL("../../.github/workflows/dast-preview.yml", import.meta.url),
    new URL("./workflow-config.mjs", import.meta.url),
  ]) {
    assert.equal(
      readFileSync(filename, "utf8").includes(
        "node scripts/security/production-version-upload-gate.mjs",
      ),
      false,
    );
  }
});

test("constructs a closed Wrangler child environment", () => {
  const child = buildWranglerChildEnvironment({
    sourceEnvironment: environment(),
    context: {
      accountId: ACCOUNT_ID,
      candidateSha: CANDIDATE,
      matchTag: SERVICE_TAG,
    },
    privateRoot: "/private/root",
    outputPath: "/private/root/output.jsonl",
  });
  assert.deepEqual(Object.keys(child).sort(), [
    "CI",
    "CLOUDFLARE_ACCOUNT_ID",
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_COMPLIANCE_REGION",
    "CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV",
    "HOME",
    "NO_COLOR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "WORKERS_CI",
    "WORKERS_CI_BRANCH",
    "WORKERS_CI_BUILD_UUID",
    "WORKERS_CI_COMMIT_SHA",
    "WRANGLER_API_ENVIRONMENT",
    "WRANGLER_CACHE_DIR",
    "WRANGLER_CI_GENERATE_PREVIEW_ALIAS",
    "WRANGLER_CI_MATCH_TAG",
    "WRANGLER_CI_OVERRIDE_NAME",
    "WRANGLER_LOG",
    "WRANGLER_LOG_PATH",
    "WRANGLER_LOG_SANITIZE",
    "WRANGLER_OUTPUT_FILE_PATH",
    "WRANGLER_SEND_ERROR_REPORTS",
    "WRANGLER_SEND_METRICS",
    "WRANGLER_WRITE_LOGS",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
  ].sort());
  assert.equal(child.WRANGLER_CI_GENERATE_PREVIEW_ALIAS, "false");
  assert.equal(child.WRANGLER_LOG, "error");
  assert.equal(child.TEMP, "/private/root/tmp");
  assert.equal(child.TMP, "/private/root/tmp");
  assert.equal(child.TMPDIR, "/private/root/tmp");
  assert.equal(child.CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV, "false");
  assert.equal(child.CLOUDFLARE_API_KEY, undefined);
  assert.equal(child.NODE_OPTIONS, undefined);
  assert.equal(child.PGID_PRODUCTION_D1_DATABASE_ID, undefined);
});

test("creates mode-0600 private files and cleans every private path", async (context) => {
  let observedConfig;
  let observedOutput;
  let observedRoot;
  const harness = localHarness(context);
  const result = await withPrivateProductionUploadWorkspace({
    generatedConfig: harness.fixture.generated,
    generatedConfigPath: harness.fixture.generatedPath,
    context: { accountId: ACCOUNT_ID, d1Uuid: D1_UUID },
    deps: harness.deps,
    inspect({ outputPath, privateConfig, privateConfigPath, privateRoot }) {
      observedConfig = privateConfigPath;
      observedOutput = outputPath;
      observedRoot = privateRoot;
      assert.equal(lstatSync(observedConfig).mode & 0o777, 0o600);
      assert.equal(lstatSync(observedOutput).mode & 0o777, 0o600);
      assert.equal(lstatSync(observedRoot).mode & 0o777, 0o700);
      assert.equal(lstatSync(path.join(observedRoot, "tmp")).mode & 0o777, 0o700);
      assert.deepEqual(JSON.parse(readFileSync(observedConfig, "utf8")), privateConfig);
      appendFileSync(observedOutput, `${JSON.stringify(outputRecord())}\n`);
      return "offline-inspected";
    },
  });
  assert.equal(result, "offline-inspected");
  assert.equal(existsSync(observedConfig), false);
  assert.equal(existsSync(observedOutput), false);
  assert.equal(existsSync(observedRoot), false);
});

test("detects private-file replacement and hardlink retention", async (context) => {
  for (const mutation of ["symlink", "hardlink"]) {
    const harness = localHarness(context);
    let observedConfig;
    let retainedPath;
    await expectCodeAsync(
      () =>
        withPrivateProductionUploadWorkspace({
          generatedConfig: harness.fixture.generated,
          generatedConfigPath: harness.fixture.generatedPath,
          context: { accountId: ACCOUNT_ID, d1Uuid: D1_UUID },
          deps: harness.deps,
          inspect({ privateConfigPath }) {
            observedConfig = privateConfigPath;
            retainedPath = `${privateConfigPath}.${mutation}`;
            if (mutation === "hardlink") {
              linkSync(privateConfigPath, retainedPath);
              return;
            }
            writeFileSync(retainedPath, "{}\n", { mode: 0o600 });
            rmSync(privateConfigPath);
            symlinkSync(retainedPath, privateConfigPath);
          },
        }),
      "PRIVATE_FILE_REPLACED",
    );
    assert.equal(existsSync(observedConfig), false);
    rmSync(retainedPath, { force: true });
  }
});

test("does not report workspace success when cleanup fails", async (context) => {
  for (const inspectFails of [false, true]) {
    const harness = localHarness(context);
    const failingFs = {
      ...importFs,
      rmSync() {},
    };
    await expectCodeAsync(
      () =>
        withPrivateProductionUploadWorkspace({
          generatedConfig: harness.fixture.generated,
          generatedConfigPath: harness.fixture.generatedPath,
          context: { accountId: ACCOUNT_ID, d1Uuid: D1_UUID },
          deps: { ...harness.deps, fs: failingFs },
          inspect() {
            if (inspectFails) throw new Error("offline inspection failed");
            return "must-not-return";
          },
        }),
      "PRIVATE_CLEANUP_FAILED",
    );
  }
});

test("evaluates synthetic evidence only as a blocked offline model", () => {
  const generated = generatedConfig("/reviewed");
  const privateConfig = derivePrivateProductionConfig(generated, {
    accountId: ACCOUNT_ID,
    d1Uuid: D1_UUID,
  });
  const before = normalizedSnapshot(privateConfig);
  const after = normalizedSnapshot(privateConfig, { uploaded: true });
  const evidence = {
    before,
    after,
    outputBytes: Buffer.from(`${JSON.stringify(outputRecord())}\n`),
    childResult: normalizedChildResult(),
    detail: after.latestVersion,
    context: {
      accountId: ACCOUNT_ID,
      d1Uuid: D1_UUID,
      matchTag: SERVICE_TAG,
      candidateSha: CANDIDATE,
      tree: TREE,
      buildCorrelationSha256: sha256(BUILD_UUID),
    },
    privateConfig,
    generatedConfig: generated,
    startedAt: NOW,
    finishedAt: NOW,
  };
  const result = evaluateOfflineProductionVersionUploadEvidence(evidence);
  assert.equal(result.status, "OFFLINE_MODEL_ONLY");
  assert.equal(result.productionExecutionBlocked, true);
  assert.equal(result.versionId, NEW_VERSION);
  assert.equal(result.buildCorrelationSha256, sha256(BUILD_UUID));
  const serialized = JSON.stringify(result);
  for (const forbidden of [ACCOUNT_ID, D1_UUID, SERVICE_TAG, "fixture", BUILD_UUID]) {
    assert.equal(serialized.includes(forbidden), false);
  }
  const contradictoryDetail = structuredClone(after.latestVersion);
  contradictoryDetail.annotations["workers/message"] = "contradictory";
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        ...evidence,
        detail: contradictoryDetail,
      }),
    "UPLOADED_VERSION_DETAIL_MISMATCH",
  );
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        ...evidence,
        privateConfig: { ...privateConfig, unreviewed: true },
      }),
    "OFFLINE_CONFIG_CONTRACT",
  );
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        ...evidence,
        context: {
          ...evidence.context,
          tree: { toString: () => TREE, unreviewed: "raw" },
        },
      }),
    "OFFLINE_CONTEXT_IDENTITY",
  );
});

test("ambiguous synthetic evidence remains an unknown outcome", () => {
  const generated = generatedConfig("/reviewed");
  const privateConfig = derivePrivateProductionConfig(generated, {
    accountId: ACCOUNT_ID,
    d1Uuid: D1_UUID,
  });
  const before = normalizedSnapshot(privateConfig);
  const after = normalizedSnapshot(privateConfig, { uploaded: true });
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        before,
        after,
        outputBytes: Buffer.alloc(0),
        childResult: normalizedChildResult({ status: 1 }),
        detail: after.latestVersion,
        context: {
          accountId: ACCOUNT_ID,
          d1Uuid: D1_UUID,
          matchTag: SERVICE_TAG,
          candidateSha: CANDIDATE,
          tree: TREE,
          buildCorrelationSha256: sha256(BUILD_UUID),
        },
        privateConfig,
        generatedConfig: generated,
        startedAt: NOW,
        finishedAt: NOW,
      }),
    "UNKNOWN_OUTCOME_VERSION_CREATED",
  );
});

test("the normalized remote boundary remains fail closed", async () => {
  const remote = createFailClosedRemoteAdapter();
  await expectCodeAsync(
    () => remote.readSnapshot(),
    "EXTERNAL_C_AND_OWNER_EXECUTION_REVIEW_REQUIRED",
  );
  await expectCodeAsync(
    () => remote.readVersion(),
    "EXTERNAL_C_AND_OWNER_EXECUTION_REVIEW_REQUIRED",
  );
});

test("pinned Wrangler identities remain immutable constants", () => {
  assert.deepEqual(PINNED_WRANGLER, {
    package: "f625bdbdfd80b77c23d0e876ce1e12c3533384de33c131887652f7f1475c9793",
    cli: "64e547d8912121a116f8109eacd3c4061e61499de32eb994df5ae62f2eb905dd",
    launcher: "780661a508810f3b65786895b1ca9aacbc4f55d329ae6b8c1e49ec8433569f77",
  });
});

test("canonical evidence excludes target identifiers and raw runtime values", () => {
  const value = canonicalJson({
    bindings: [{ database_id: "approved-target", name: "DB", type: "d1" }],
    status: "OFFLINE_MODEL_ONLY",
  });
  assert.equal(value.includes(ACCOUNT_ID), false);
  assert.equal(value.includes(D1_UUID), false);
  assert.equal(value.includes(SERVICE_TAG), false);
});
