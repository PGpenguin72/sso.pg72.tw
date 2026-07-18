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
  ASSET_RETRY_RESIDUAL,
  BOUNDED_RETRY_ACCEPTANCE_SCOPE,
  BUILD_UUID_ACCEPTANCE_RESIDUAL,
  MAX_DUPLICATE_INACTIVE_VERSIONS,
  MAX_VERSION_CREATE_ATTEMPTS,
  PINNED_WRANGLER,
  PRODUCTION_EXECUTION_BLOCKERS,
  PRODUCTION_OWNER_ID,
  PRODUCTION_WORKER_NAME,
  SCRIPT_IDENTITY_RESIDUAL,
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
  validateBoundedRetryOwnerAcceptance,
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
const NEW_VERSION_2 = "66666666-6666-4666-8666-666666666666";
const NEW_VERSION_3 = "77777777-7777-4777-8777-777777777777";
const SERVICE_TAG = "service-tag-fixture";
const OBSERVED_SCRIPT_ETAG = "observed-script-etag-fixture";
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
    scriptEtag = OBSERVED_SCRIPT_ETAG,
  } = {},
) {
  return {
    annotations: {
      "workers/message": message,
      "workers/tag": tag,
    },
    id,
    metadata: { hasPreview: false },
    scriptEtag,
    resources: {
      bindings: runtimeBindings(config, secretNames),
      script_runtime: {
        compatibility_date: config.compatibility_date,
        compatibility_flags: [...config.compatibility_flags],
      },
    },
  };
}

function normalizedSnapshot(
  config,
  { uploaded = false, addedVersionIds = uploaded ? [NEW_VERSION] : [] } = {},
) {
  return {
    activeVersion: versionDetail(ACTIVE_VERSION, config),
    deployments: [
      {
        id: "44444444-4444-4444-8444-444444444444",
        versions: [{ percentage: 100, version_id: ACTIVE_VERSION }],
      },
    ],
    latestVersion: addedVersionIds.length > 0
      ? versionDetail(addedVersionIds[0], config, {
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
    versions: [
      ...addedVersionIds.map((id) => ({ id })),
      { id: ACTIVE_VERSION },
    ],
    workerName: PRODUCTION_WORKER_NAME,
  };
}

function offlineContext(overrides = {}) {
  return {
    accountId: ACCOUNT_ID,
    d1Uuid: D1_UUID,
    matchTag: SERVICE_TAG,
    candidateSha: CANDIDATE,
    tree: TREE,
    workersBuildUuid: BUILD_UUID,
    buildCorrelationSha256: sha256(BUILD_UUID),
    ...overrides,
  };
}

function ownerAcceptance(overrides = {}) {
  const baseline = {
    schemaVersion: 1,
    decision: "accept-exact-bounded-inactive-version-duplicates-only",
    scope: BOUNDED_RETRY_ACCEPTANCE_SCOPE,
    ownerId: PRODUCTION_OWNER_ID,
    workerName: PRODUCTION_WORKER_NAME,
    scriptIdentity: {
      etagRule: "all-added-versions-share-one-observed-script-etag",
      residual: SCRIPT_IDENTITY_RESIDUAL,
    },
    candidateSha: CANDIDATE,
    candidateTree: TREE,
    targetBindingSha256: sha256(
      Buffer.from(
        canonicalJson({
          accountId: ACCOUNT_ID,
          d1Uuid: D1_UUID,
          serviceTag: SERVICE_TAG,
          workerName: PRODUCTION_WORKER_NAME,
        }),
      ),
    ),
    workersBuild: {
      uuidBinding: "current-workers-build",
      sha256Binding: "sha256-current-workers-build",
      residual: BUILD_UUID_ACCEPTANCE_RESIDUAL,
    },
    wrangler: {
      version: "4.110.0",
      packageSha256: PINNED_WRANGLER.package,
      cliSha256: PINNED_WRANGLER.cli,
      launcherSha256: PINNED_WRANGLER.launcher,
    },
    issuedAt: new Date(NOW - 1_000).toISOString(),
    expiresAt: new Date(NOW + 60_000).toISOString(),
    maximumVersionCreateAttempts: MAX_VERSION_CREATE_ATTEMPTS,
    maximumDuplicateInactiveVersions: MAX_DUPLICATE_INACTIVE_VERSIONS,
    assetRetryResidual: ASSET_RETRY_RESIDUAL,
  };
  return {
    ...baseline,
    ...overrides,
    workersBuild: overrides.workersBuild ?? baseline.workersBuild,
    wrangler: overrides.wrangler ?? baseline.wrangler,
  };
}

function uploadedDetails(config, versionIds = [NEW_VERSION]) {
  return versionIds.map((id) =>
    versionDetail(id, config, {
      tag: CANDIDATE,
      message: `${UPLOAD_MESSAGE_PREFIX}${CANDIDATE}`,
    }),
  );
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

function offlineEvidence({
  addedVersionIds = [NEW_VERSION],
  outputBytes =
    addedVersionIds.length === 0
      ? Buffer.alloc(0)
      : Buffer.from(
          `${JSON.stringify(
            outputRecord({ version_id: addedVersionIds[0] }),
          )}\n`,
        ),
  childResult = normalizedChildResult(),
  details,
  context = offlineContext(),
  acceptance = ownerAcceptance(),
} = {}) {
  const generated = generatedConfig("/reviewed");
  const privateConfig = derivePrivateProductionConfig(generated, {
    accountId: ACCOUNT_ID,
    d1Uuid: D1_UUID,
  });
  const before = normalizedSnapshot(privateConfig);
  const after = normalizedSnapshot(privateConfig, { addedVersionIds });
  return {
    before,
    after,
    outputBytes,
    childResult,
    details: details ?? uploadedDetails(privateConfig, addedVersionIds),
    context,
    ownerAcceptance: acceptance,
    privateConfig,
    generatedConfig: generated,
    startedAt: NOW,
    finishedAt: NOW,
    evaluatedAt: NOW,
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
    "bounded-pinned-wrangler-internal-retry-owner-acceptance-review",
    "child-process-tree-custody-review",
    "sealed-wrangler-executable-dependency-closure",
    "normalized-script-content-manifest-and-provenance-review",
    "trusted-git-binary-and-config-custody",
  ]);
});

test("validates local identity using only injected offline dependencies", async (context) => {
  const harness = localHarness(context);
  const result = await validateHarness(harness);
  assert.equal(result.head, CANDIDATE);
  assert.equal(result.tree, TREE);
  assert.equal(result.workersBuildUuid, BUILD_UUID);
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

test("classifies bounded inactive versions with unchanged control-plane state", () => {
  const config = derivePrivateProductionConfig(generatedConfig("/reviewed"), {
    accountId: ACCOUNT_ID,
    d1Uuid: D1_UUID,
  });
  const before = normalizedSnapshot(config);
  const after = normalizedSnapshot(config, { uploaded: true });
  const outputRecord = { version_id: NEW_VERSION };
  const success = normalizedChildResult();
  assert.deepEqual(
    classifyPostflight({ before, after, outputRecord, childResult: success }),
    {
      status: "VERIFIED_INACTIVE_VERSION",
      addedVersionIds: [NEW_VERSION],
      duplicateInactiveVersionCount: 0,
      outputVersionId: NEW_VERSION,
    },
  );
  for (const [code, mutate] of [
    ["UNEXPECTED_SUBDOMAIN_OR_IDENTITY_MUTATION", (value) => (value.subdomain.enabled = true)],
    ["UNEXPECTED_SCRIPT_SETTINGS_MUTATION", (value) => value.scriptSettings.tags.push("drift")],
    ["UNEXPECTED_ACTIVE_DEPLOYMENT_MUTATION", (value) => (value.deployments[0].id = NEW_VERSION)],
    [
      "BOUNDED_RETRY_VERSION_LIMIT_EXCEEDED",
      (value) =>
        value.versions.unshift(
          { id: "88888888-8888-4888-8888-888888888888" },
          { id: "99999999-9999-4999-8999-999999999999" },
          { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
        ),
    ],
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
    "FOREIGN_VERSION_INVENTORY_MUTATION",
  );
  assert.deepEqual(
    classifyPostflight({
      before,
      after,
      outputRecord: null,
      childResult: normalizedChildResult({ status: 1 }),
    }),
    {
      status: "REVIEW_REQUIRED",
      addedVersionIds: [NEW_VERSION],
      duplicateInactiveVersionCount: 0,
      outputVersionId: null,
    },
  );
  assert.deepEqual(
    classifyPostflight({
      before,
      after: before,
      outputRecord: null,
      childResult: normalizedChildResult({ status: 1 }),
    }),
    {
      status: "NO_MUTATION_RETRY_REQUIRES_OWNER",
      addedVersionIds: [],
      duplicateInactiveVersionCount: 0,
      outputVersionId: null,
    },
  );
  assert.deepEqual(
    classifyPostflight({
      before,
      after,
      outputRecord,
      childResult: normalizedChildResult({ overflow: true }),
    }),
    {
      status: "REVIEW_REQUIRED",
      addedVersionIds: [NEW_VERSION],
      duplicateInactiveVersionCount: 0,
      outputVersionId: NEW_VERSION,
    },
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
      observedScriptEtag: OBSERVED_SCRIPT_ETAG,
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
        observedScriptEtag: OBSERVED_SCRIPT_ETAG,
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
          observedScriptEtag: OBSERVED_SCRIPT_ETAG,
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

test("validates an exact, expiring owner acceptance and resolved build binding", () => {
  const context = offlineContext();
  const valid = ownerAcceptance();
  const result = validateBoundedRetryOwnerAcceptance({
    acceptance: valid,
    context,
    evaluatedAt: NOW,
  });
  assert.equal(result.buildCorrelationSha256, sha256(BUILD_UUID));
  assert.match(result.bindingSha256, /^[0-9a-f]{64}$/);
  for (const [code, acceptance] of [
    ["OWNER_ACCEPTANCE_SCHEMA", { ...valid, unreviewed: true }],
    ["OWNER_ACCEPTANCE_SCOPE", ownerAcceptance({ ownerId: "other" })],
    ["OWNER_ACCEPTANCE_SCOPE", ownerAcceptance({ candidateTree: "c".repeat(40) })],
    ["OWNER_ACCEPTANCE_SCOPE", ownerAcceptance({ targetBindingSha256: "d".repeat(64) })],
    ["OWNER_ACCEPTANCE_SCOPE", ownerAcceptance({ maximumVersionCreateAttempts: 4 })],
    ["OWNER_ACCEPTANCE_SCOPE", ownerAcceptance({ maximumDuplicateInactiveVersions: 3 })],
    ["OWNER_ACCEPTANCE_SCOPE", ownerAcceptance({ assetRetryResidual: "assets-may-retry" })],
    [
      "OWNER_ACCEPTANCE_SCRIPT_IDENTITY",
      ownerAcceptance({
        scriptIdentity: {
          ...valid.scriptIdentity,
          etagRule: "any-observed-etag",
        },
      }),
    ],
    [
      "OWNER_ACCEPTANCE_BUILD_BINDING",
      ownerAcceptance({
        workersBuild: {
          ...valid.workersBuild,
          uuidBinding: "any-workers-build",
        },
      }),
    ],
    [
      "OWNER_ACCEPTANCE_TOOL_IDENTITY",
      ownerAcceptance({
        wrangler: { ...valid.wrangler, cliSha256: "e".repeat(64) },
      }),
    ],
    [
      "OWNER_ACCEPTANCE_STALE",
      ownerAcceptance({ expiresAt: new Date(NOW).toISOString() }),
    ],
    [
      "OWNER_ACCEPTANCE_STALE",
      ownerAcceptance({
        issuedAt: new Date(NOW - 1_000).toISOString(),
        expiresAt: new Date(NOW + 24 * 60 * 60 * 1_000).toISOString(),
      }),
    ],
  ]) {
    expectCode(
      () =>
        validateBoundedRetryOwnerAcceptance({
          acceptance,
          context,
          evaluatedAt: NOW,
        }),
      code,
    );
  }
  expectCode(
    () =>
      validateBoundedRetryOwnerAcceptance({
        acceptance: valid,
        context: offlineContext({ workersBuildUuid: NEW_VERSION }),
        evaluatedAt: NOW,
      }),
    "OFFLINE_CONTEXT_IDENTITY",
  );
});

test("evaluates exact output as one blocked verified inactive version", () => {
  const evidence = offlineEvidence();
  const result = evaluateOfflineProductionVersionUploadEvidence(evidence);
  assert.equal(result.evidenceMode, "OFFLINE_MODEL_ONLY");
  assert.equal(result.status, "VERIFIED_INACTIVE_VERSION");
  assert.equal(result.productionExecutionBlocked, true);
  assert.deepEqual(result.addedVersionIds, [NEW_VERSION]);
  assert.equal(result.verifiedVersionId, NEW_VERSION);
  assert.equal(result.duplicateInactiveVersionCount, 0);
  assert.equal(result.wrapperRetryAuthorized, false);
  assert.equal(result.pinnedToolInternalRetryAccepted, true);
  assert.equal(result.assetIdentityVerified, false);
  assert.equal(result.scriptArtifactIdentityVerified, false);
  assert.equal(result.assetRetryResidual, ASSET_RETRY_RESIDUAL);
  assert.equal(result.scriptIdentityResidual, SCRIPT_IDENTITY_RESIDUAL);
  assert.equal(
    result.observedScriptEtagSha256,
    sha256(OBSERVED_SCRIPT_ETAG),
  );
  assert.equal(result.buildCorrelationSha256, sha256(BUILD_UUID));
  const serialized = JSON.stringify(result);
  for (const forbidden of [ACCOUNT_ID, D1_UUID, SERVICE_TAG, "fixture", BUILD_UUID]) {
    assert.equal(serialized.includes(forbidden), false);
  }
  const alternateEtagEvidence = offlineEvidence();
  alternateEtagEvidence.after.latestVersion.scriptEtag = "alternate-observed-etag";
  alternateEtagEvidence.details[0].scriptEtag = "alternate-observed-etag";
  const alternateEtagResult =
    evaluateOfflineProductionVersionUploadEvidence(alternateEtagEvidence);
  assert.notEqual(
    alternateEtagResult.ownerAcceptanceResolutionSha256,
    result.ownerAcceptanceResolutionSha256,
  );
  assert.equal(
    alternateEtagResult.observedScriptEtagSha256,
    sha256("alternate-observed-etag"),
  );
  const contradictoryDetail = structuredClone(evidence.after.latestVersion);
  contradictoryDetail.annotations["workers/message"] = "contradictory";
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        ...evidence,
        details: [contradictoryDetail],
      }),
    "UPLOADED_VERSION_DETAIL_MISMATCH",
  );
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        ...evidence,
        privateConfig: { ...evidence.privateConfig, unreviewed: true },
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

test("accepts at most two fully verified inactive duplicate versions", () => {
  const versionIds = [NEW_VERSION_3, NEW_VERSION_2, NEW_VERSION];
  const result = evaluateOfflineProductionVersionUploadEvidence(
    offlineEvidence({ addedVersionIds: versionIds }),
  );
  assert.equal(result.status, "VERIFIED_INACTIVE_VERSION");
  assert.deepEqual(result.addedVersionIds, versionIds);
  assert.equal(result.verifiedVersionId, NEW_VERSION_3);
  assert.equal(result.duplicateInactiveVersionCount, 2);
  assert.equal(result.acceptedMaximumVersionCreateAttempts, 3);
  assert.equal(result.acceptedMaximumDuplicateInactiveVersions, 2);
});

test("an older added output ID remains review-required", () => {
  const versionIds = [NEW_VERSION_2, NEW_VERSION];
  const result = evaluateOfflineProductionVersionUploadEvidence(
    offlineEvidence({
      addedVersionIds: versionIds,
      outputBytes: Buffer.from(
        `${JSON.stringify(outputRecord({ version_id: NEW_VERSION }))}\n`,
      ),
    }),
  );
  assert.equal(result.status, "REVIEW_REQUIRED");
  assert.deepEqual(result.addedVersionIds, versionIds);
  assert.equal(result.reportedVersionId, NEW_VERSION);
  assert.equal(result.verifiedVersionId, null);
});

test("output loss or nonzero child state returns a bounded review receipt", () => {
  for (const evidence of [
    offlineEvidence({ outputBytes: Buffer.alloc(0) }),
    offlineEvidence({ childResult: normalizedChildResult({ status: 1 }) }),
  ]) {
    const result = evaluateOfflineProductionVersionUploadEvidence(evidence);
    assert.equal(result.status, "REVIEW_REQUIRED");
    assert.deepEqual(result.addedVersionIds, [NEW_VERSION]);
    assert.equal(result.verifiedVersionId, null);
    assert.equal(result.productionExecutionBlocked, true);
    assert.equal(result.wrapperRetryAuthorized, false);
  }
});

test("zero mutation requires a new owner decision and rejects contradictory output", () => {
  const evidence = offlineEvidence({ addedVersionIds: [] });
  const result = evaluateOfflineProductionVersionUploadEvidence(evidence);
  assert.equal(result.status, "NO_MUTATION_RETRY_REQUIRES_OWNER");
  assert.deepEqual(result.addedVersionIds, []);
  assert.equal(result.verifiedVersionId, null);
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        ...evidence,
        outputBytes: Buffer.from(`${JSON.stringify(outputRecord())}\n`),
      }),
    "OUTPUT_VERSION_NOT_CREATED",
  );
  const latestDrift = structuredClone(evidence.after);
  latestDrift.latestVersion.annotations["workers/message"] = "drift";
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        ...evidence,
        after: latestDrift,
      }),
    "FOREIGN_LATEST_VERSION_MUTATION",
  );
});

test("present malformed or foreign output fails instead of becoming output loss", () => {
  const evidence = offlineEvidence();
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        ...evidence,
        outputBytes: Buffer.from("{not-json}\n"),
      }),
    "WRANGLER_OUTPUT_JSON",
  );
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        ...evidence,
        outputBytes: Buffer.from(
          `${JSON.stringify(outputRecord({ version_id: NEW_VERSION_2 }))}\n`,
        ),
      }),
    "OUTPUT_VERSION_NOT_ADDED",
  );
});

test("every added detail must share one observed etag and runtime inventory", () => {
  const versionIds = [NEW_VERSION_2, NEW_VERSION];
  const evidence = offlineEvidence({ addedVersionIds: versionIds });
  const etagDrift = structuredClone(evidence.details);
  etagDrift[1].scriptEtag = "foreign-etag";
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        ...evidence,
        details: etagDrift,
      }),
    "UPLOADED_SCRIPT_ETAG_MISMATCH",
  );
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        ...evidence,
        details: evidence.details.slice(0, 1),
      }),
    "UPLOADED_VERSION_DETAILS_INCOMPLETE",
  );
  const bindingDrift = structuredClone(evidence.details);
  bindingDrift[1].resources.bindings.find(({ type }) => type === "plain_text").text =
    "foreign";
  expectCode(
    () =>
      evaluateOfflineProductionVersionUploadEvidence({
        ...evidence,
        details: bindingDrift,
      }),
    "UPLOADED_BINDING_INVENTORY_MISMATCH",
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
