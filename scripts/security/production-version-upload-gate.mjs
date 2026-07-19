import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";

export const PRODUCTION_WORKER_NAME = "pg72-id";
export const PRODUCTION_OWNER_ID = "PGpenguin72";
export const UPLOAD_MESSAGE_PREFIX = "PGID release ";
export const WRANGLER_OUTPUT_MAX_BYTES = 8 * 1024;
export const MAX_VERSION_CREATE_ATTEMPTS = 3;
export const MAX_DUPLICATE_INACTIVE_VERSIONS = 2;
export const MAX_UPLOAD_PREFLIGHT_AGE_MS = 10 * 60 * 1000;
export const MAX_UPLOAD_ACTION_DURATION_MS = 10 * 60 * 1000;
export const MAX_UPLOAD_POSTFLIGHT_DELAY_MS = 10 * 60 * 1000;
export const MAX_UPLOAD_EVALUATION_DELAY_MS = 10 * 60 * 1000;
export const BOUNDED_RETRY_ACCEPTANCE_SCOPE =
  "pgid-production-version-upload:bounded-inactive-retry:v1";
export const ASSET_RETRY_RESIDUAL =
  "content-addressed-asset-retry-requires-reviewed-normalized-adapter-and-exact-manifest-proof";
export const BUILD_UUID_ACCEPTANCE_RESIDUAL =
  "current-build-selector-does-not-prove-owner-preapproval-of-an-assigned-uuid;retrigger-replay-injection-provenance-and-custody-remain-production-blocking";
export const SCRIPT_IDENTITY_RESIDUAL =
  "observed-script-etag-equality-does-not-prove-local-artifact-identity;sealed-toolchain-and-normalized-content-manifest-proof-remain-production-blocking";
export const PRODUCTION_EXECUTION_BLOCKERS = Object.freeze([
  "external-c-normalized-api-adapter-review",
  "multi-endpoint-snapshot-provenance-and-single-writer-review",
  "owner-workers-builds-trigger-and-token-custody",
  "bounded-pinned-wrangler-internal-retry-owner-acceptance-review",
  "child-process-tree-custody-review",
  "sealed-wrangler-executable-dependency-closure",
  "normalized-script-content-manifest-and-provenance-review",
  "trusted-git-binary-and-config-custody",
]);

export const PINNED_WRANGLER = Object.freeze({
  package: "f625bdbdfd80b77c23d0e876ce1e12c3533384de33c131887652f7f1475c9793",
  cli: "64e547d8912121a116f8109eacd3c4061e61499de32eb994df5ae62f2eb905dd",
  launcher: "780661a508810f3b65786895b1ca9aacbc4f55d329ae6b8c1e49ec8433569f77",
});

const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ACCOUNT_ID_PATTERN = /^[0-9a-f]{32}$/;
const SAFE_OPAQUE_TAG_PATTERN = /^[\x21-\x7e]{1,256}$/;
const SAFE_CONTROL_TEXT_PATTERN = /^[\x20-\x7e]{1,1024}$/;
const WRANGLER_VERSION = "4.110.0";
const OWNER_ACCEPTANCE_DECISION =
  "accept-exact-bounded-inactive-version-duplicates-only";
const BUILD_UUID_BINDING = "current-workers-build";
const BUILD_UUID_SHA256_BINDING = "sha256-current-workers-build";
const SCRIPT_ETAG_RULE = "all-added-versions-share-one-observed-script-etag";
const OWNER_ACCEPTANCE_MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;
const REQUIRED_OUTPUT_KEYS = Object.freeze([
  "timestamp",
  "type",
  "version",
  "version_id",
  "worker_name",
  "worker_name_overridden",
  "worker_tag",
]);
const GENERATED_CONFIG_RELATIVE_PATH = "apps/sso/dist/pg72_id/wrangler.json";
const RELEASE_POLICY_RELATIVE_PATH = "security/release-policy.json";
const APPROVED_PARENT_ENVIRONMENT_KEYS = new Set([
  "CI",
  "CLOUDFLARE_ACCOUNT_ID",
  "CLOUDFLARE_API_TOKEN",
  "PGID_PRODUCTION_ACCOUNT_ID",
  "PGID_PRODUCTION_D1_DATABASE_ID",
  "WORKERS_CI",
  "WORKERS_CI_BRANCH",
  "WORKERS_CI_BUILD_UUID",
  "WORKERS_CI_COMMIT_SHA",
  "WRANGLER_CI_MATCH_TAG",
  "WRANGLER_CI_OVERRIDE_NAME",
]);
const CONTROLLED_PARENT_ENVIRONMENT_PREFIXES = Object.freeze([
  "CF_",
  "CLOUDFLARE_",
  "DYLD_",
  "LD_",
  "NODE_",
  "PGID_PRODUCTION_",
  "SSL_",
  "WORKERS_CI",
  "WRANGLER_",
]);
const FORBIDDEN_PARENT_ENVIRONMENT_KEYS = new Set([
  "ALL_PROXY",
  "BASH_ENV",
  "ENV",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "NO_PROXY",
  "all_proxy",
  "https_proxy",
  "http_proxy",
  "no_proxy",
]);

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));

export class ProductionUploadGateError extends Error {
  constructor(code) {
    super(code);
    this.name = "ProductionUploadGateError";
    this.code = code;
  }
}

function fail(code) {
  throw new ProductionUploadGateError(code);
}

function requireCondition(condition, code) {
  if (!condition) fail(code);
}

function matchesPattern(value, pattern) {
  return typeof value === "string" && pattern.test(value);
}

function compareExactText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function exactKeys(value, expected) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())
  );
}

function mode(stat) {
  return stat.mode & 0o777;
}

function isInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return (
    relative === "" ||
    (relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative))
  );
}

function readExactRegularFile(fs, filename, code) {
  let stat;
  try {
    stat = fs.lstatSync(filename);
  } catch {
    fail(code);
  }
  requireCondition(stat.isFile() && !stat.isSymbolicLink(), code);
  try {
    return fs.readFileSync(filename);
  } catch {
    fail(code);
  }
}

function writeExclusivePrivateFile(fs, filename, bytes) {
  const flags =
    fs.constants.O_WRONLY |
    fs.constants.O_CREAT |
    fs.constants.O_EXCL |
    (fs.constants.O_NOFOLLOW ?? 0);
  let descriptor;
  try {
    descriptor = fs.openSync(filename, flags, 0o600);
    fs.fchmodSync(descriptor, 0o600);
    if (bytes.length > 0) fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    const stat = fs.fstatSync(descriptor);
    requireCondition(
      stat.isFile() && mode(stat) === 0o600 && stat.nlink === 1,
      "PRIVATE_FILE_MODE",
    );
    return {
      descriptor,
      dev: stat.dev,
      ino: stat.ino,
      initialSize: stat.size,
      initialSha256: sha256(bytes),
    };
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {}
    }
    if (error instanceof ProductionUploadGateError) throw error;
    fail("PRIVATE_FILE_CREATE");
  }
}

function verifyPrivateFileIdentity(
  fs,
  filename,
  identity,
  expectedBytes,
  { unchanged = false } = {},
) {
  let stat;
  try {
    stat = fs.lstatSync(filename);
  } catch {
    fail("PRIVATE_FILE_REPLACED");
  }
  requireCondition(
    stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.dev === identity.dev &&
      stat.ino === identity.ino &&
      stat.nlink === 1 &&
      mode(stat) === 0o600 &&
      stat.size <= expectedBytes &&
      (!unchanged || stat.size === identity.initialSize),
    "PRIVATE_FILE_REPLACED",
  );
  if (unchanged) {
    requireCondition(
      sha256(fs.readFileSync(filename)) === identity.initialSha256,
      "PRIVATE_FILE_REPLACED",
    );
  }
}

function closePrivateIdentity(fs, identity) {
  if (!identity || identity.descriptor === undefined) return true;
  try {
    fs.closeSync(identity.descriptor);
    identity.descriptor = undefined;
    return true;
  } catch {
    return false;
  }
}

function removePrivatePath(fs, filename) {
  if (!filename) return true;
  try {
    fs.rmSync(filename, { force: true, recursive: true });
    return !fs.existsSync(filename);
  } catch {
    return false;
  }
}

function validateAccountId(value, code) {
  requireCondition(matchesPattern(value, ACCOUNT_ID_PATTERN), code);
  return value;
}

function validateD1Uuid(value, code) {
  requireCondition(matchesPattern(value, UUID_PATTERN), code);
  requireCondition(value !== "00000000-0000-0000-0000-000000000001", code);
  return value;
}

function validateOpaqueTag(value, code) {
  requireCondition(
    matchesPattern(value, SAFE_OPAQUE_TAG_PATTERN),
    code,
  );
  return value;
}

export function validateProductionEnvironment(environment) {
  requireCondition(environment.GITHUB_ACTIONS === undefined, "GITHUB_ACTIONS_FORBIDDEN");
  requireCondition(environment.CI === "true", "CI_IDENTITY");
  requireCondition(environment.WORKERS_CI === "1", "CI_IDENTITY");
  requireCondition(environment.WORKERS_CI_BRANCH === "main", "CI_BRANCH");
  requireCondition(
    matchesPattern(environment.WORKERS_CI_BUILD_UUID, UUID_PATTERN),
    "CI_BUILD_UUID",
  );
  requireCondition(
    matchesPattern(environment.WORKERS_CI_COMMIT_SHA, SHA_PATTERN),
    "CI_SHA",
  );
  requireCondition(
    typeof environment.CLOUDFLARE_API_TOKEN === "string" &&
      environment.CLOUDFLARE_API_TOKEN.length > 0 &&
      environment.CLOUDFLARE_API_TOKEN.length <= 4096 &&
      !/[\x00-\x1f\x7f]/.test(environment.CLOUDFLARE_API_TOKEN),
    "API_TOKEN_MISSING",
  );
  const accountId = validateAccountId(
    environment.CLOUDFLARE_ACCOUNT_ID,
    "ACCOUNT_ID_INVALID",
  );
  requireCondition(
    validateAccountId(
      environment.PGID_PRODUCTION_ACCOUNT_ID,
      "APPROVED_ACCOUNT_ID_INVALID",
    ) === accountId,
    "ACCOUNT_ID_MISMATCH",
  );
  const d1Uuid = validateD1Uuid(
    environment.PGID_PRODUCTION_D1_DATABASE_ID,
    "D1_UUID_INVALID",
  );
  requireCondition(
    environment.WRANGLER_CI_OVERRIDE_NAME === PRODUCTION_WORKER_NAME,
    "WORKER_NAME_MISMATCH",
  );
  const matchTag = validateOpaqueTag(
    environment.WRANGLER_CI_MATCH_TAG,
    "MATCH_TAG_INVALID",
  );
  for (const key of Object.keys(environment)) {
    const controlled =
      FORBIDDEN_PARENT_ENVIRONMENT_KEYS.has(key) ||
      CONTROLLED_PARENT_ENVIRONMENT_PREFIXES.some((prefix) =>
        key.startsWith(prefix),
      );
    requireCondition(
      !controlled || APPROVED_PARENT_ENVIRONMENT_KEYS.has(key),
      "FORBIDDEN_ENVIRONMENT",
    );
  }
  return {
    accountId,
    d1Uuid,
    matchTag,
    candidateSha: environment.WORKERS_CI_COMMIT_SHA,
    workersBuildUuid: environment.WORKERS_CI_BUILD_UUID,
    buildCorrelationSha256: sha256(environment.WORKERS_CI_BUILD_UUID),
    apiToken: environment.CLOUDFLARE_API_TOKEN,
  };
}

function canonicalTimestamp(value, code) {
  requireCondition(typeof value === "string", code);
  const timestamp = Date.parse(value);
  requireCondition(
    Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value,
    code,
  );
  return timestamp;
}

function canonicalActionTime(value) {
  requireCondition(
    Number.isSafeInteger(value) &&
      value >= 0 &&
      Number.isFinite(new Date(value).getTime()),
    "UPLOAD_ACTION_TIME_SCHEMA",
  );
  return value;
}

export function validateBoundedRetryOwnerAcceptance({
  acceptance,
  context,
  evaluatedAt,
}) {
  requireCondition(
    exactKeys(context, [
      "accountId",
      "buildCorrelationSha256",
      "candidateSha",
      "d1Uuid",
      "matchTag",
      "tree",
      "workersBuildUuid",
    ]) &&
      matchesPattern(context.candidateSha, SHA_PATTERN) &&
      matchesPattern(context.tree, SHA_PATTERN) &&
      matchesPattern(context.accountId, ACCOUNT_ID_PATTERN) &&
      matchesPattern(context.d1Uuid, UUID_PATTERN) &&
      context.d1Uuid !== "00000000-0000-0000-0000-000000000001" &&
      matchesPattern(context.matchTag, SAFE_OPAQUE_TAG_PATTERN) &&
      matchesPattern(context.workersBuildUuid, UUID_PATTERN) &&
      matchesPattern(context.buildCorrelationSha256, DIGEST_PATTERN) &&
      sha256(context.workersBuildUuid) === context.buildCorrelationSha256,
    "OFFLINE_CONTEXT_IDENTITY",
  );
  requireCondition(
    Number.isSafeInteger(evaluatedAt) && evaluatedAt >= 0,
    "OWNER_ACCEPTANCE_EVALUATION_TIME",
  );
  requireCondition(
    exactKeys(acceptance, [
      "assetRetryResidual",
      "candidateSha",
      "candidateTree",
      "decision",
      "expiresAt",
      "issuedAt",
      "maximumDuplicateInactiveVersions",
      "maximumVersionCreateAttempts",
      "ownerId",
      "schemaVersion",
      "scriptIdentity",
      "scope",
      "targetBindingSha256",
      "workerName",
      "workersBuild",
      "wrangler",
    ]),
    "OWNER_ACCEPTANCE_SCHEMA",
  );
  requireCondition(
    acceptance.schemaVersion === 1 &&
      acceptance.decision === OWNER_ACCEPTANCE_DECISION &&
      acceptance.scope === BOUNDED_RETRY_ACCEPTANCE_SCOPE &&
      acceptance.ownerId === PRODUCTION_OWNER_ID &&
      acceptance.workerName === PRODUCTION_WORKER_NAME &&
      acceptance.candidateSha === context.candidateSha &&
      acceptance.candidateTree === context.tree &&
      acceptance.targetBindingSha256 ===
        sha256(
          Buffer.from(
            canonicalJson({
              accountId: context.accountId,
              d1Uuid: context.d1Uuid,
              serviceTag: context.matchTag,
              workerName: PRODUCTION_WORKER_NAME,
            }),
          ),
        ) &&
      acceptance.maximumVersionCreateAttempts === MAX_VERSION_CREATE_ATTEMPTS &&
      acceptance.maximumDuplicateInactiveVersions ===
        MAX_DUPLICATE_INACTIVE_VERSIONS &&
      acceptance.assetRetryResidual === ASSET_RETRY_RESIDUAL,
    "OWNER_ACCEPTANCE_SCOPE",
  );
  requireCondition(
    exactKeys(acceptance.scriptIdentity, ["etagRule", "residual"]) &&
      acceptance.scriptIdentity.etagRule === SCRIPT_ETAG_RULE &&
      acceptance.scriptIdentity.residual === SCRIPT_IDENTITY_RESIDUAL,
    "OWNER_ACCEPTANCE_SCRIPT_IDENTITY",
  );
  requireCondition(
    exactKeys(acceptance.workersBuild, [
      "residual",
      "sha256Binding",
      "uuidBinding",
    ]) &&
      acceptance.workersBuild.uuidBinding === BUILD_UUID_BINDING &&
      acceptance.workersBuild.sha256Binding === BUILD_UUID_SHA256_BINDING &&
      acceptance.workersBuild.residual === BUILD_UUID_ACCEPTANCE_RESIDUAL,
    "OWNER_ACCEPTANCE_BUILD_BINDING",
  );
  requireCondition(
    exactKeys(acceptance.wrangler, [
      "cliSha256",
      "launcherSha256",
      "packageSha256",
      "version",
    ]) &&
      acceptance.wrangler.version === WRANGLER_VERSION &&
      acceptance.wrangler.packageSha256 === PINNED_WRANGLER.package &&
      acceptance.wrangler.cliSha256 === PINNED_WRANGLER.cli &&
      acceptance.wrangler.launcherSha256 === PINNED_WRANGLER.launcher,
    "OWNER_ACCEPTANCE_TOOL_IDENTITY",
  );
  const issuedAt = canonicalTimestamp(
    acceptance.issuedAt,
    "OWNER_ACCEPTANCE_ISSUED_AT",
  );
  const expiresAt = canonicalTimestamp(
    acceptance.expiresAt,
    "OWNER_ACCEPTANCE_EXPIRES_AT",
  );
  requireCondition(
    issuedAt <= evaluatedAt &&
      evaluatedAt < expiresAt &&
      issuedAt < expiresAt &&
      expiresAt - issuedAt <= OWNER_ACCEPTANCE_MAX_LIFETIME_MS,
    "OWNER_ACCEPTANCE_STALE",
  );
  return Object.freeze({
    bindingSha256: sha256(
      Buffer.from(
        canonicalJson({
          acceptance,
          resolvedBuildCorrelationSha256: context.buildCorrelationSha256,
        }),
      ),
    ),
    buildCorrelationSha256: context.buildCorrelationSha256,
  });
}

export function derivePrivateProductionConfig(
  generatedConfig,
  { accountId, d1Uuid },
) {
  requireCondition(
    generatedConfig?.name === PRODUCTION_WORKER_NAME,
    "GENERATED_WORKER_NAME",
  );
  requireCondition(
    Array.isArray(generatedConfig.d1_databases) &&
      generatedConfig.d1_databases.length === 1 &&
      generatedConfig.d1_databases[0]?.binding === "PG72_ID_DB" &&
      generatedConfig.d1_databases[0]?.database_id ===
        "00000000-0000-0000-0000-000000000001",
    "GENERATED_D1_CONTRACT",
  );
  const privateConfig = structuredClone(generatedConfig);
  privateConfig.d1_databases[0].database_id = validateD1Uuid(
    d1Uuid,
    "D1_UUID_INVALID",
  );
  privateConfig.workers_dev = false;
  privateConfig.preview_urls = false;
  privateConfig.account_id = validateAccountId(accountId, "ACCOUNT_ID_INVALID");
  return privateConfig;
}

export function normalizePrivateProductionConfig(
  privateConfig,
  { accountId, d1Uuid },
) {
  const normalized = structuredClone(privateConfig);
  requireCondition(normalized.account_id === accountId, "PRIVATE_ACCOUNT_DELTA");
  requireCondition(normalized.workers_dev === false, "PRIVATE_SUBDOMAIN_DELTA");
  requireCondition(normalized.preview_urls === false, "PRIVATE_PREVIEW_DELTA");
  requireCondition(
    Array.isArray(normalized.d1_databases) &&
      normalized.d1_databases.length === 1 &&
      normalized.d1_databases[0]?.binding === "PG72_ID_DB" &&
      normalized.d1_databases[0]?.database_id === d1Uuid,
    "PRIVATE_D1_DELTA",
  );
  delete normalized.account_id;
  delete normalized.workers_dev;
  delete normalized.preview_urls;
  normalized.d1_databases[0].database_id =
    "00000000-0000-0000-0000-000000000001";
  return normalized;
}

function productionPolicyErrors(environment) {
  const errors = [];
  const worker = environment?.worker;
  if (
    environment?.sourceConfig !== "apps/sso/wrangler.jsonc" ||
    environment?.generatedConfig !== GENERATED_CONFIG_RELATIVE_PATH ||
    worker?.name !== PRODUCTION_WORKER_NAME ||
    typeof worker?.main?.generated !== "string" ||
    !Array.isArray(worker?.compatibilityFlags)
  ) {
    return ["production policy identity drifted"];
  }
  for (const entry of worker.vars ?? []) {
    if (entry.type !== "plain-var") errors.push("plain var type drifted");
  }
  for (const entry of worker.secrets ?? []) {
    if (entry.type !== "secret") errors.push("secret type drifted");
  }
  for (const entry of worker.d1 ?? []) {
    if (
      entry.type !== "d1" ||
      entry.target?.databaseId?.contract !== "reviewed-nonworking-placeholder" ||
      !/^00000000-0000-0000-0000-00000000000[1-9]$/.test(
        entry.target?.databaseId?.value,
      )
    ) {
      errors.push("D1 policy contract drifted");
    }
  }
  for (const entry of worker.queues?.producers ?? []) {
    if (entry.type !== "queue-producer") errors.push("queue producer type drifted");
  }
  for (const entry of worker.queues?.consumers ?? []) {
    if (entry.type !== "queue-consumer") errors.push("queue consumer type drifted");
  }
  for (const entry of worker.rateLimits ?? []) {
    if (entry.type !== "rate-limit") errors.push("rate limit type drifted");
  }
  for (const route of worker.routes ?? []) {
    if (route.type !== "custom-domain") errors.push("route type drifted");
  }
  if (worker.assets?.type !== "assets") errors.push("assets type drifted");
  if (
    !Array.isArray(worker.triggers?.crons) ||
    worker.triggers.crons.length === 0 ||
    worker.triggers.crons.some(
      (cron) => typeof cron !== "string" || cron.length === 0,
    )
  ) {
    errors.push("cron trigger contract drifted");
  }
  return errors;
}

function varsObject(records) {
  return Object.fromEntries(records.map(({ name, value }) => [name, value]));
}

function generatedD1(records) {
  return records.map((entry) => ({
    binding: entry.name,
    database_name: entry.target.databaseName,
    database_id: entry.target.databaseId.value,
    migrations_dir: entry.target.generatedMigrationsDirectory,
  }));
}

function generatedQueues(queues) {
  return {
    producers: queues.producers.map((entry) => ({
      binding: entry.name,
      queue: entry.target,
    })),
    consumers: queues.consumers.map((entry) => ({
      queue: entry.target,
      max_batch_size: entry.maxBatchSize,
      max_batch_timeout: entry.maxBatchTimeout,
      max_retries: entry.maxRetries,
      dead_letter_queue: entry.deadLetterTarget,
    })),
  };
}

function generatedRateLimits(records) {
  return records.map((entry) => ({
    name: entry.name,
    namespace_id: entry.target,
    simple: { limit: entry.limit, period: entry.period },
  }));
}

function generatedRoutes(records) {
  return records.map((entry) => ({
    pattern: entry.pattern,
    custom_domain: entry.customDomain,
  }));
}

export function expectedGeneratedProductionConfig(releasePolicy, root = repoRoot) {
  requireCondition(
    releasePolicy?.schemaVersion === 2 &&
      productionPolicyErrors(releasePolicy.environments?.production).length === 0,
    "RELEASE_POLICY_CONTRACT",
  );
  const environment = releasePolicy.environments.production;
  const worker = environment.worker;
  const sourceConfigPath = path.join(root, environment.sourceConfig);
  return {
    configPath: sourceConfigPath,
    userConfigPath: sourceConfigPath,
    topLevelName: worker.name,
    definedEnvironments: [],
    legacy_env: true,
    compatibility_date: worker.compatibilityDate,
    compatibility_flags: worker.compatibilityFlags,
    jsx_factory: "React.createElement",
    jsx_fragment: "React.Fragment",
    rules: [{ type: "ESModule", globs: ["**/*.js", "**/*.mjs"] }],
    name: worker.name,
    main: worker.main.generated,
    routes: generatedRoutes(worker.routes),
    triggers: worker.triggers ?? {},
    assets: {
      binding: worker.assets.name,
      not_found_handling: worker.assets.notFoundHandling,
      run_worker_first: worker.assets.runWorkerFirst,
      directory: worker.assets.generatedDirectory,
    },
    vars: varsObject(worker.vars),
    secrets: { required: worker.secrets.map(({ name }) => name) },
    durable_objects: { bindings: [] },
    workflows: [],
    migrations: [],
    exports: {},
    kv_namespaces: [],
    cloudchamber: {},
    send_email: [],
    queues: generatedQueues(worker.queues),
    r2_buckets: [],
    d1_databases: generatedD1(worker.d1),
    vectorize: [],
    ai_search_namespaces: [],
    ai_search: [],
    agent_memory: [],
    hyperdrive: [],
    services: [],
    analytics_engine_datasets: [],
    dispatch_namespaces: [],
    mtls_certificates: [],
    pipelines: [],
    secrets_store_secrets: [],
    artifacts: [],
    unsafe_hello_world: [],
    flagship: [],
    worker_loaders: [],
    ratelimits: generatedRateLimits(worker.rateLimits),
    vpc_services: [],
    vpc_networks: [],
    logfwdr: { bindings: [] },
    observability: worker.observability,
    python_modules: { exclude: ["**/*.pyc"] },
    dev: {
      ip: "localhost",
      local_protocol: "http",
      upstream_protocol: "http",
      enable_containers: true,
      generate_types: false,
    },
    no_bundle: true,
  };
}

function containsRemoteBinding(value) {
  if (!value || typeof value !== "object") return false;
  return Object.entries(value).some(
    ([key, child]) =>
      (key === "remote" && child === true) || containsRemoteBinding(child),
  );
}

function expectedWranglerPaths(repositoryRoot) {
  const packageRoot = path.join(
    repositoryRoot,
    "apps",
    "sso",
    "node_modules",
    "wrangler",
  );
  return {
    packageRoot,
    package: path.join(packageRoot, "package.json"),
    cli: path.join(packageRoot, "wrangler-dist", "cli.js"),
    launcher: path.join(packageRoot, "bin", "wrangler.js"),
  };
}

async function exactGitOutput(runProcess, repositoryRoot, args, code) {
  const result = await runProcess("git", args, {
    cwd: repositoryRoot,
    env: {
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
      HOME: os.tmpdir(),
      PATH: process.env.PATH ?? "",
    },
    maxBytes: 64 * 1024,
    timeoutMs: 30_000,
  });
  requireCondition(
    result && result.status === 0 && result.signal === null && !result.timedOut,
    code,
  );
  return result.stdout.toString("utf8").trim();
}

export async function validateLocalReleaseContext({
  repositoryRoot = repoRoot,
  environment,
  deps,
  wranglerPaths = expectedWranglerPaths(repositoryRoot),
  expectedWranglerDigests = PINNED_WRANGLER,
}) {
  const production = validateProductionEnvironment(environment);
  requireCondition(
    Array.isArray(deps.execArgv) && deps.execArgv.length === 0,
    "NODE_EXEC_ARGV_FORBIDDEN",
  );
  requireCondition(
    String(deps.nodeVersion).split(".")[0] === "24",
    "NODE_VERSION",
  );
  const head = await exactGitOutput(
    deps.runProcess,
    repositoryRoot,
    ["rev-parse", "HEAD^{commit}"],
    "GIT_HEAD",
  );
  const tree = await exactGitOutput(
    deps.runProcess,
    repositoryRoot,
    ["rev-parse", "HEAD^{tree}"],
    "GIT_TREE",
  );
  const status = await exactGitOutput(
    deps.runProcess,
    repositoryRoot,
    ["status", "--porcelain=v1", "--untracked-files=all"],
    "GIT_STATUS",
  );
  requireCondition(head === production.candidateSha, "CI_SHA_MISMATCH");
  requireCondition(matchesPattern(tree, SHA_PATTERN), "GIT_TREE");
  requireCondition(status === "", "GIT_DIRTY");

  let resolvedWranglerRoot;
  try {
    resolvedWranglerRoot = deps.fs.realpathSync(wranglerPaths.packageRoot);
  } catch {
    fail("WRANGLER_PACKAGE_PATH");
  }
  requireCondition(
    isInside(deps.fs.realpathSync(repositoryRoot), resolvedWranglerRoot),
    "WRANGLER_PACKAGE_PATH",
  );
  const resolvedWranglerPaths = {
    package: path.join(resolvedWranglerRoot, "package.json"),
    cli: path.join(resolvedWranglerRoot, "wrangler-dist", "cli.js"),
    launcher: path.join(resolvedWranglerRoot, "bin", "wrangler.js"),
  };
  for (const key of ["package", "cli", "launcher"]) {
    const bytes = readExactRegularFile(
      deps.fs,
      resolvedWranglerPaths[key],
      "WRANGLER_IDENTITY",
    );
    requireCondition(
      sha256(bytes) === expectedWranglerDigests[key],
      "WRANGLER_IDENTITY",
    );
  }

  let releasePolicy;
  let generatedConfig;
  try {
    releasePolicy = JSON.parse(
      readExactRegularFile(
        deps.fs,
        path.join(repositoryRoot, RELEASE_POLICY_RELATIVE_PATH),
        "RELEASE_POLICY",
      ).toString("utf8"),
    );
    requireCondition(
      releasePolicy.schemaVersion === 2 &&
        productionPolicyErrors(releasePolicy.environments?.production).length === 0,
      "RELEASE_POLICY_CONTRACT",
    );
    const generatedConfigPath = path.join(
      repositoryRoot,
      releasePolicy.environments.production.generatedConfig,
    );
    generatedConfig = JSON.parse(
      readExactRegularFile(
        deps.fs,
        generatedConfigPath,
        "GENERATED_CONFIG",
      ).toString("utf8"),
    );
    requireCondition(
      isDeepStrictEqual(
        generatedConfig,
        expectedGeneratedProductionConfig(releasePolicy, repositoryRoot),
      ) &&
        generatedConfig.account_id === undefined &&
        !containsRemoteBinding(generatedConfig),
      "GENERATED_CONFIG_CONTRACT",
    );
  } catch (error) {
    if (error instanceof ProductionUploadGateError) throw error;
    fail("GENERATED_CONFIG");
  }
  const generatedConfigPath = path.join(
    repositoryRoot,
    releasePolicy.environments.production.generatedConfig,
  );
  return {
    ...production,
    head,
    tree,
    generatedConfig,
    generatedConfigPath,
    wranglerCliPath: resolvedWranglerPaths.cli,
    wranglerCliSha256: expectedWranglerDigests.cli,
  };
}

function validateDeployment(deployment) {
  requireCondition(
    deployment &&
      typeof deployment === "object" &&
      exactKeys(deployment, ["id", "versions"]) &&
      matchesPattern(deployment.id, UUID_PATTERN) &&
      Array.isArray(deployment.versions) &&
      deployment.versions.length === 1 &&
      exactKeys(deployment.versions[0], ["percentage", "version_id"]) &&
      deployment.versions[0]?.percentage === 100 &&
      matchesPattern(deployment.versions[0]?.version_id, UUID_PATTERN),
    "REMOTE_DEPLOYMENT_SCHEMA_REVIEW_REQUIRED",
  );
  return deployment;
}

function validateVersionSummary(version) {
  requireCondition(
    version &&
      typeof version === "object" &&
      exactKeys(version, ["id", "number"]) &&
      matchesPattern(version.id, UUID_PATTERN) &&
      Number.isSafeInteger(version.number) &&
      version.number > 0,
    "REMOTE_VERSION_SCHEMA_REVIEW_REQUIRED",
  );
  return version;
}

function validateVersionDetail(detail) {
  requireCondition(
    detail &&
      typeof detail === "object" &&
      exactKeys(detail, [
        "annotations",
        "id",
        "metadata",
        "resources",
        "scriptEtag",
      ]) &&
      matchesPattern(detail.id, UUID_PATTERN) &&
      matchesPattern(detail.scriptEtag, SAFE_OPAQUE_TAG_PATTERN) &&
      detail.resources &&
      typeof detail.resources === "object" &&
      exactKeys(detail.resources, ["bindings", "script_runtime"]) &&
      Array.isArray(detail.resources.bindings) &&
      detail.resources.script_runtime &&
      typeof detail.resources.script_runtime === "object" &&
      exactKeys(detail.resources.script_runtime, [
        "compatibility_date",
        "compatibility_flags",
      ]) &&
      typeof detail.resources.script_runtime.compatibility_date === "string" &&
      Array.isArray(detail.resources.script_runtime.compatibility_flags) &&
      detail.metadata &&
      typeof detail.metadata === "object" &&
      exactKeys(detail.metadata, ["hasPreview"]) &&
      typeof detail.metadata.hasPreview === "boolean" &&
      detail.annotations &&
      typeof detail.annotations === "object" &&
      exactKeys(detail.annotations, ["workers/message", "workers/tag"]) &&
      typeof detail.annotations["workers/message"] === "string" &&
      typeof detail.annotations["workers/tag"] === "string",
    "REMOTE_RUNTIME_SCHEMA_REVIEW_REQUIRED",
  );
  const flags = detail.resources.script_runtime.compatibility_flags;
  requireCondition(
    flags.every((flag) => typeof flag === "string" && flag.length > 0) &&
      new Set(flags).size === flags.length &&
      isDeepStrictEqual(flags, [...flags].sort(compareExactText)),
    "REMOTE_RUNTIME_ORDER_REVIEW_REQUIRED",
  );
  requireCondition(
    isDeepStrictEqual(detail.resources.bindings, sortBindings(detail.resources.bindings)),
    "REMOTE_BINDING_ORDER_REVIEW_REQUIRED",
  );
  return detail;
}

function canonicalOrderedUnique(values, identity, duplicateCode, orderCode) {
  const identities = values.map(identity);
  requireCondition(new Set(identities).size === identities.length, duplicateCode);
  requireCondition(
    isDeepStrictEqual(identities, [...identities].sort(compareExactText)),
    orderCode,
  );
}

function validateObservation(observation) {
  requireCondition(
    exactKeys(observation, [
      "apiProvenanceVerified",
      "atomicSnapshotVerified",
      "controlPlanePairingSha256",
      "correlationSha256",
      "endpointSetSha256",
      "firstObservedAt",
      "lastObservedAt",
      "paginationStructureClosed",
      "permissionScopeVerified",
      "phase",
      "singleWriterVerified",
      "tokenBindingSha256",
    ]) &&
      ["preflight", "postflight"].includes(observation.phase) &&
      matchesPattern(observation.controlPlanePairingSha256, DIGEST_PATTERN) &&
      matchesPattern(observation.correlationSha256, DIGEST_PATTERN) &&
      matchesPattern(observation.endpointSetSha256, DIGEST_PATTERN) &&
      matchesPattern(observation.tokenBindingSha256, DIGEST_PATTERN) &&
      observation.paginationStructureClosed === true &&
      observation.apiProvenanceVerified === false &&
      observation.atomicSnapshotVerified === false &&
      observation.permissionScopeVerified === false &&
      observation.singleWriterVerified === false,
    "REMOTE_OBSERVATION_PROVENANCE_REVIEW_REQUIRED",
  );
  const firstObservedAt = canonicalTimestamp(
    observation.firstObservedAt,
    "REMOTE_OBSERVATION_TIME_REVIEW_REQUIRED",
  );
  const lastObservedAt = canonicalTimestamp(
    observation.lastObservedAt,
    "REMOTE_OBSERVATION_TIME_REVIEW_REQUIRED",
  );
  requireCondition(
    firstObservedAt <= lastObservedAt &&
      lastObservedAt - firstObservedAt <= 5 * 60 * 1000,
    "REMOTE_OBSERVATION_TIME_REVIEW_REQUIRED",
  );
}

function validateControlPlaneCollections(snapshot) {
  requireCondition(Array.isArray(snapshot.routes), "REMOTE_ROUTE_SCHEMA_REVIEW_REQUIRED");
  for (const route of snapshot.routes) {
    requireCondition(
      exactKeys(route, ["id", "pattern", "script"]) &&
        matchesPattern(route.id, UUID_PATTERN) &&
        matchesPattern(route.pattern, SAFE_CONTROL_TEXT_PATTERN) &&
        route.script === PRODUCTION_WORKER_NAME,
      "REMOTE_ROUTE_SCHEMA_REVIEW_REQUIRED",
    );
  }
  canonicalOrderedUnique(
    snapshot.routes,
    ({ pattern }) => pattern,
    "REMOTE_ROUTE_DUPLICATE",
    "REMOTE_ROUTE_ORDER_REVIEW_REQUIRED",
  );
  requireCondition(
    new Set(snapshot.routes.map(({ id }) => id)).size === snapshot.routes.length,
    "REMOTE_ROUTE_DUPLICATE",
  );

  requireCondition(
    Array.isArray(snapshot.customDomains),
    "REMOTE_CUSTOM_DOMAIN_SCHEMA_REVIEW_REQUIRED",
  );
  for (const domain of snapshot.customDomains) {
    requireCondition(
      exactKeys(domain, ["environment", "hostname", "id", "service", "zoneId"]) &&
        matchesPattern(domain.id, ACCOUNT_ID_PATTERN) &&
        matchesPattern(domain.zoneId, ACCOUNT_ID_PATTERN) &&
        typeof domain.hostname === "string" &&
        /^[a-z0-9.-]{1,253}$/.test(domain.hostname) &&
        domain.service === PRODUCTION_WORKER_NAME &&
        domain.environment === "production",
      "REMOTE_CUSTOM_DOMAIN_SCHEMA_REVIEW_REQUIRED",
    );
  }
  canonicalOrderedUnique(
    snapshot.customDomains,
    ({ hostname }) => hostname,
    "REMOTE_CUSTOM_DOMAIN_DUPLICATE",
    "REMOTE_CUSTOM_DOMAIN_ORDER_REVIEW_REQUIRED",
  );
  requireCondition(
    new Set(snapshot.customDomains.map(({ id }) => id)).size ===
      snapshot.customDomains.length,
    "REMOTE_CUSTOM_DOMAIN_DUPLICATE",
  );

  requireCondition(
    Array.isArray(snapshot.schedules),
    "REMOTE_SCHEDULE_SCHEMA_REVIEW_REQUIRED",
  );
  for (const schedule of snapshot.schedules) {
    requireCondition(
      exactKeys(schedule, ["createdOn", "cron", "modifiedOn"]) &&
        matchesPattern(schedule.cron, SAFE_CONTROL_TEXT_PATTERN) &&
        schedule.cron.length <= 256,
      "REMOTE_SCHEDULE_SCHEMA_REVIEW_REQUIRED",
    );
    canonicalTimestamp(schedule.createdOn, "REMOTE_SCHEDULE_SCHEMA_REVIEW_REQUIRED");
    canonicalTimestamp(schedule.modifiedOn, "REMOTE_SCHEDULE_SCHEMA_REVIEW_REQUIRED");
  }
  canonicalOrderedUnique(
    snapshot.schedules,
    ({ cron }) => cron,
    "REMOTE_SCHEDULE_DUPLICATE",
    "REMOTE_SCHEDULE_ORDER_REVIEW_REQUIRED",
  );

  requireCondition(
    Array.isArray(snapshot.queueConsumers),
    "REMOTE_QUEUE_CONSUMER_SCHEMA_REVIEW_REQUIRED",
  );
  for (const consumer of snapshot.queueConsumers) {
    requireCondition(
      exactKeys(consumer, [
        "consumerId",
        "deadLetterQueue",
        "maxBatchSize",
        "maxBatchTimeout",
        "maxRetries",
        "queueName",
        "scriptName",
      ]) &&
        matchesPattern(consumer.consumerId, ACCOUNT_ID_PATTERN) &&
        (consumer.deadLetterQueue === null ||
          matchesPattern(consumer.deadLetterQueue, SAFE_CONTROL_TEXT_PATTERN)) &&
        Number.isSafeInteger(consumer.maxBatchSize) &&
        consumer.maxBatchSize > 0 &&
        Number.isSafeInteger(consumer.maxBatchTimeout) &&
        consumer.maxBatchTimeout >= 0 &&
        Number.isSafeInteger(consumer.maxRetries) &&
        consumer.maxRetries >= 0 &&
        matchesPattern(consumer.queueName, SAFE_CONTROL_TEXT_PATTERN) &&
        consumer.scriptName === PRODUCTION_WORKER_NAME,
      "REMOTE_QUEUE_CONSUMER_SCHEMA_REVIEW_REQUIRED",
    );
  }
  canonicalOrderedUnique(
    snapshot.queueConsumers,
    ({ queueName }) => queueName,
    "REMOTE_QUEUE_CONSUMER_DUPLICATE",
    "REMOTE_QUEUE_CONSUMER_ORDER_REVIEW_REQUIRED",
  );
  requireCondition(
    new Set(snapshot.queueConsumers.map(({ consumerId }) => consumerId)).size ===
      snapshot.queueConsumers.length,
    "REMOTE_QUEUE_CONSUMER_DUPLICATE",
  );

  requireCondition(
    Array.isArray(snapshot.queueTriggers),
    "REMOTE_QUEUE_TRIGGER_SCHEMA_REVIEW_REQUIRED",
  );
  for (const trigger of snapshot.queueTriggers) {
    requireCondition(
      exactKeys(trigger, ["environment", "queueName", "scriptName"]) &&
        trigger.environment === "production" &&
        matchesPattern(trigger.queueName, SAFE_CONTROL_TEXT_PATTERN) &&
        trigger.scriptName === PRODUCTION_WORKER_NAME,
      "REMOTE_QUEUE_TRIGGER_SCHEMA_REVIEW_REQUIRED",
    );
  }
  canonicalOrderedUnique(
    snapshot.queueTriggers,
    ({ queueName }) => queueName,
    "REMOTE_QUEUE_TRIGGER_DUPLICATE",
    "REMOTE_QUEUE_TRIGGER_ORDER_REVIEW_REQUIRED",
  );
}

export function validateNormalizedSnapshot(
  snapshot,
  { accountId, matchTag },
) {
  requireCondition(
    snapshot &&
      snapshot.schemaVersion === 2 &&
      exactKeys(snapshot, [
        "accountId",
        "activeVersion",
        "customDomains",
        "deployments",
        "latestVersion",
        "observation",
        "queueConsumers",
        "queueTriggers",
        "routes",
        "schedules",
        "schemaVersion",
        "scriptSettings",
        "serviceTag",
        "subdomain",
        "versions",
        "workerName",
      ]),
    "REMOTE_SNAPSHOT_SCHEMA_REVIEW_REQUIRED",
  );
  requireCondition(
    matchesPattern(accountId, ACCOUNT_ID_PATTERN) &&
      snapshot.accountId === accountId &&
      snapshot.workerName === PRODUCTION_WORKER_NAME &&
      snapshot.serviceTag === matchTag,
    "REMOTE_WORKER_IDENTITY",
  );
  validateObservation(snapshot.observation);
  requireCondition(
    exactKeys(snapshot.subdomain, ["enabled", "previews_enabled"]) &&
      snapshot.subdomain.enabled === false &&
      snapshot.subdomain.previews_enabled === false,
    "REMOTE_PREVIEW_STATE",
  );
  requireCondition(
    snapshot.scriptSettings &&
      typeof snapshot.scriptSettings === "object" &&
      !Array.isArray(snapshot.scriptSettings) &&
      exactKeys(snapshot.scriptSettings, [
        "logpush",
        "observability",
        "tags",
        "tail_consumers",
      ]) &&
      (snapshot.scriptSettings.logpush === null ||
        typeof snapshot.scriptSettings.logpush === "boolean") &&
      (snapshot.scriptSettings.observability === null ||
        (typeof snapshot.scriptSettings.observability === "object" &&
          !Array.isArray(snapshot.scriptSettings.observability) &&
          exactKeys(snapshot.scriptSettings.observability, [
            "enabled",
            "headSamplingRate",
          ]) &&
          typeof snapshot.scriptSettings.observability.enabled === "boolean" &&
          (snapshot.scriptSettings.observability.headSamplingRate === null ||
            (typeof snapshot.scriptSettings.observability.headSamplingRate === "number" &&
              Number.isFinite(snapshot.scriptSettings.observability.headSamplingRate) &&
              snapshot.scriptSettings.observability.headSamplingRate >= 0 &&
              snapshot.scriptSettings.observability.headSamplingRate <= 1)))) &&
      Array.isArray(snapshot.scriptSettings.tags) &&
      snapshot.scriptSettings.tags.every(
        (tag) =>
          matchesPattern(tag, SAFE_CONTROL_TEXT_PATTERN) &&
          !tag.startsWith("cf:service=") &&
          !tag.startsWith("cf:environment="),
      ) &&
      new Set(snapshot.scriptSettings.tags).size === snapshot.scriptSettings.tags.length &&
      isDeepStrictEqual(
        snapshot.scriptSettings.tags,
        [...snapshot.scriptSettings.tags].sort(compareExactText),
      ) &&
      Array.isArray(snapshot.scriptSettings.tail_consumers) &&
      snapshot.scriptSettings.tail_consumers.every(
        (consumer) =>
          exactKeys(consumer, ["environment", "service"]) &&
          consumer.environment === "production" &&
          matchesPattern(consumer.service, SAFE_CONTROL_TEXT_PATTERN),
      ),
    "REMOTE_TAG_STATE",
  );
  canonicalOrderedUnique(
    snapshot.scriptSettings.tail_consumers,
    ({ environment, service }) => `${service}\0${environment}`,
    "REMOTE_TAIL_CONSUMER_DUPLICATE",
    "REMOTE_TAIL_CONSUMER_ORDER_REVIEW_REQUIRED",
  );
  validateControlPlaneCollections(snapshot);
  requireCondition(
    Array.isArray(snapshot.deployments) && snapshot.deployments.length === 1,
    "REMOTE_DEPLOYMENT_SCHEMA_REVIEW_REQUIRED",
  );
  const activeDeployment = validateDeployment(snapshot.deployments[0]);
  requireCondition(
    Array.isArray(snapshot.versions) && snapshot.versions.length > 0,
    "REMOTE_VERSION_SCHEMA_REVIEW_REQUIRED",
  );
  const versionIds = new Set();
  let priorVersionNumber = Number.POSITIVE_INFINITY;
  for (const version of snapshot.versions) {
    validateVersionSummary(version);
    requireCondition(!versionIds.has(version.id), "REMOTE_VERSION_DUPLICATE");
    requireCondition(
      version.number < priorVersionNumber,
      "REMOTE_VERSION_ORDER_REVIEW_REQUIRED",
    );
    versionIds.add(version.id);
    priorVersionNumber = version.number;
  }
  const activeVersion = validateVersionDetail(snapshot.activeVersion);
  requireCondition(
    activeVersion.id === activeDeployment.versions[0].version_id,
    "REMOTE_ACTIVE_VERSION_MISMATCH",
  );
  const latestVersion = validateVersionDetail(snapshot.latestVersion);
  requireCondition(
    latestVersion.id === snapshot.versions[0].id,
    "REMOTE_LATEST_VERSION_MISMATCH",
  );
  requireCondition(
    versionIds.has(activeVersion.id) &&
      activeDeployment.versions.every(({ version_id }) =>
        versionIds.has(version_id),
      ),
    "REMOTE_DEPLOYMENT_VERSION_INVENTORY_MISMATCH",
  );
  return snapshot;
}

function normalizeBinding(binding) {
  requireCondition(
    binding && typeof binding === "object" && !Array.isArray(binding),
    "REMOTE_BINDING_SCHEMA_REVIEW_REQUIRED",
  );
  const { name, type } = binding;
  requireCondition(
    matchesPattern(name, SAFE_CONTROL_TEXT_PATTERN) &&
      matchesPattern(type, SAFE_CONTROL_TEXT_PATTERN),
    "REMOTE_BINDING_SCHEMA_REVIEW_REQUIRED",
  );
  if (type === "secret_text") {
    requireCondition(
      exactKeys(binding, ["name", "type"]),
      "REMOTE_SECRET_REDACTION_SCHEMA_REVIEW_REQUIRED",
    );
    return { name, type };
  }
  if (type === "plain_text") {
    requireCondition(
      exactKeys(binding, ["name", "text", "type"]) &&
        typeof binding.text === "string",
      "REMOTE_BINDING_SCHEMA_REVIEW_REQUIRED",
    );
    return { name, text: binding.text, type };
  }
  if (type === "d1") {
    requireCondition(
      exactKeys(binding, ["database_id", "name", "type"]),
      "REMOTE_BINDING_SCHEMA_REVIEW_REQUIRED",
    );
    requireCondition(
      matchesPattern(binding.database_id, UUID_PATTERN),
      "REMOTE_BINDING_SCHEMA_REVIEW_REQUIRED",
    );
    return { database_id: binding.database_id, name, type };
  }
  if (type === "queue") {
    requireCondition(
      exactKeys(binding, ["name", "queue_name", "type"]) &&
      typeof binding.queue_name === "string" && binding.queue_name.length > 0,
      "REMOTE_BINDING_SCHEMA_REVIEW_REQUIRED",
    );
    return { name, queue_name: binding.queue_name, type };
  }
  if (type === "ratelimit") {
    requireCondition(
      exactKeys(binding, ["name", "namespace_id", "simple", "type"]) &&
      typeof binding.namespace_id === "string" &&
        binding.simple &&
        exactKeys(binding.simple, ["limit", "period"]) &&
        typeof binding.simple.limit === "number" &&
        typeof binding.simple.period === "number",
      "REMOTE_BINDING_SCHEMA_REVIEW_REQUIRED",
    );
    return {
      name,
      namespace_id: binding.namespace_id,
      simple: {
        limit: binding.simple.limit,
        period: binding.simple.period,
      },
      type,
    };
  }
  if (type === "assets") {
    requireCondition(
      exactKeys(binding, ["name", "type"]),
      "REMOTE_BINDING_SCHEMA_REVIEW_REQUIRED",
    );
    return { name, type };
  }
  fail("REMOTE_BINDING_TYPE_UNREVIEWED");
}

function sortBindings(bindings) {
  const normalized = bindings
    .map((binding) => normalizeBinding(binding))
    .sort((left, right) =>
      compareExactText(`${left.type}\0${left.name}`, `${right.type}\0${right.name}`),
    );
  const names = new Set();
  for (const binding of normalized) {
    requireCondition(!names.has(binding.name), "REMOTE_BINDING_DUPLICATE");
    names.add(binding.name);
  }
  return normalized;
}

function expectedBindings(privateConfig, latestVersion) {
  const latest = sortBindings(latestVersion.resources.bindings);
  const secretNames = latest
    .filter(({ type }) => type === "secret_text")
    .map(({ name }) => name)
    .sort();
  const requiredSecretNames = [...(privateConfig.secrets?.required ?? [])].sort();
  requireCondition(
    isDeepStrictEqual(secretNames, requiredSecretNames),
    "RUNTIME_SECRET_INVENTORY_MISMATCH",
  );
  const expected = [];
  for (const [name, text] of Object.entries(privateConfig.vars ?? {})) {
    expected.push({ name, text: String(text), type: "plain_text" });
  }
  for (const database of privateConfig.d1_databases ?? []) {
    expected.push({
      database_id: database.database_id,
      name: database.binding,
      type: "d1",
    });
  }
  for (const queue of privateConfig.queues?.producers ?? []) {
    expected.push({ name: queue.binding, queue_name: queue.queue, type: "queue" });
  }
  for (const rateLimit of privateConfig.ratelimits ?? []) {
    expected.push({
      name: rateLimit.name,
      namespace_id: rateLimit.namespace_id,
      simple: {
        limit: rateLimit.simple.limit,
        period: rateLimit.simple.period,
      },
      type: "ratelimit",
    });
  }
  if (privateConfig.assets?.binding) {
    expected.push({ name: privateConfig.assets.binding, type: "assets" });
  }
  for (const name of secretNames) expected.push({ name, type: "secret_text" });
  return expected.sort((left, right) =>
    compareExactText(`${left.type}\0${left.name}`, `${right.type}\0${right.name}`),
  );
}

export function verifyUploadedVersion({
  detail,
  versionId,
  candidateSha,
  message,
  privateConfig,
  latestVersion,
  observedScriptEtag,
}) {
  validateVersionDetail(detail);
  requireCondition(detail.id === versionId, "UPLOADED_VERSION_ID_MISMATCH");
  requireCondition(
    matchesPattern(observedScriptEtag, SAFE_OPAQUE_TAG_PATTERN) &&
      detail.scriptEtag === observedScriptEtag,
    "UPLOADED_SCRIPT_ETAG_MISMATCH",
  );
  // Pinned Wrangler reads annotations here, but the public OpenAPI model is
  // incomplete. Keep this exact and fail closed until external C verifies it.
  requireCondition(
    detail.annotations?.["workers/tag"] === candidateSha &&
      detail.annotations?.["workers/message"] === message,
    "REMOTE_VERSION_ANNOTATION_SCHEMA_REVIEW_REQUIRED",
  );
  requireCondition(
    detail.metadata.hasPreview === false,
    "REMOTE_VERSION_PREVIEW_SCHEMA_REVIEW_REQUIRED",
  );
  requireCondition(
    detail.resources.script_runtime.compatibility_date ===
      privateConfig.compatibility_date &&
      isDeepStrictEqual(
        detail.resources.script_runtime.compatibility_flags ?? [],
        privateConfig.compatibility_flags ?? [],
      ),
    "UPLOADED_RUNTIME_MISMATCH",
  );
  const actualBindings = sortBindings(detail.resources.bindings);
  const expected = expectedBindings(privateConfig, latestVersion);
  requireCondition(
    isDeepStrictEqual(actualBindings, expected),
    "UPLOADED_BINDING_INVENTORY_MISMATCH",
  );
  return actualBindings.map((binding) =>
    binding.type === "d1" ? { ...binding, database_id: "approved-target" } : binding,
  );
}

export function parseWranglerOutputJsonl(
  bytes,
  { matchTag, startedAt, finishedAt },
) {
  requireCondition(Buffer.isBuffer(bytes), "WRANGLER_OUTPUT_TYPE");
  requireCondition(
    bytes.length > 0 && bytes.length <= WRANGLER_OUTPUT_MAX_BYTES,
    "WRANGLER_OUTPUT_SIZE",
  );
  const text = bytes.toString("utf8");
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  requireCondition(lines.length === 1 && lines[0].length > 0, "WRANGLER_OUTPUT_LINES");
  let record;
  try {
    record = JSON.parse(lines[0]);
  } catch {
    fail("WRANGLER_OUTPUT_JSON");
  }
  requireCondition(exactKeys(record, REQUIRED_OUTPUT_KEYS), "WRANGLER_OUTPUT_SCHEMA");
  requireCondition(
    record.type === "version-upload" &&
      record.version === 1 &&
      record.worker_name === PRODUCTION_WORKER_NAME &&
      record.worker_tag === matchTag &&
      record.worker_name_overridden === false &&
      matchesPattern(record.version_id, UUID_PATTERN),
    "WRANGLER_OUTPUT_IDENTITY",
  );
  const timestamp = Date.parse(record.timestamp);
  requireCondition(
    Number.isFinite(timestamp) && timestamp >= startedAt && timestamp <= finishedAt,
    "WRANGLER_OUTPUT_TIMESTAMP",
  );
  return record;
}

function versionMap(versions) {
  const result = new Map();
  for (const version of versions) {
    validateVersionSummary(version);
    requireCondition(!result.has(version.id), "REMOTE_VERSION_DUPLICATE");
    result.set(version.id, canonicalJson(version));
  }
  return result;
}

function validateUploadSnapshotTimeBracket({
  before,
  after,
  startedAt,
  finishedAt,
  evaluatedAt,
}) {
  const uploadStartedAt = canonicalActionTime(startedAt);
  const uploadFinishedAt = canonicalActionTime(finishedAt);
  const evaluationTime = canonicalActionTime(evaluatedAt);
  const preflightFirstObservedAt = canonicalTimestamp(
    before?.observation?.firstObservedAt,
    "UPLOAD_ACTION_TIME_BRACKET",
  );
  const preflightLastObservedAt = canonicalTimestamp(
    before?.observation?.lastObservedAt,
    "UPLOAD_ACTION_TIME_BRACKET",
  );
  const postflightFirstObservedAt = canonicalTimestamp(
    after?.observation?.firstObservedAt,
    "UPLOAD_ACTION_TIME_BRACKET",
  );
  const postflightLastObservedAt = canonicalTimestamp(
    after?.observation?.lastObservedAt,
    "UPLOAD_ACTION_TIME_BRACKET",
  );

  requireCondition(
    preflightFirstObservedAt <= preflightLastObservedAt &&
      preflightLastObservedAt <= uploadStartedAt &&
      uploadStartedAt <= uploadFinishedAt &&
      uploadFinishedAt <= postflightFirstObservedAt &&
      postflightFirstObservedAt <= postflightLastObservedAt &&
      postflightLastObservedAt <= evaluationTime &&
      uploadStartedAt - preflightLastObservedAt <=
        MAX_UPLOAD_PREFLIGHT_AGE_MS &&
      uploadFinishedAt - uploadStartedAt <=
        MAX_UPLOAD_ACTION_DURATION_MS &&
      postflightFirstObservedAt - uploadFinishedAt <=
        MAX_UPLOAD_POSTFLIGHT_DELAY_MS &&
      evaluationTime - postflightLastObservedAt <=
        MAX_UPLOAD_EVALUATION_DELAY_MS,
    "UPLOAD_ACTION_TIME_BRACKET",
  );
}

export function classifyPostflight({
  before,
  after,
  outputRecord,
  childResult,
  startedAt,
  finishedAt,
  evaluatedAt,
}) {
  validateUploadSnapshotTimeBracket({
    before,
    after,
    startedAt,
    finishedAt,
    evaluatedAt,
  });
  requireCondition(
    exactKeys(childResult, ["overflow", "signal", "status", "timedOut"]) &&
      (childResult.status === null || Number.isInteger(childResult.status)) &&
      (childResult.signal === null || typeof childResult.signal === "string") &&
      typeof childResult.timedOut === "boolean" &&
      typeof childResult.overflow === "boolean",
    "CHILD_RESULT_SCHEMA",
  );
  requireCondition(
    before.accountId === after.accountId &&
      before.workerName === after.workerName &&
      before.serviceTag === after.serviceTag &&
      isDeepStrictEqual(before.subdomain, after.subdomain),
    "UNEXPECTED_SUBDOMAIN_OR_IDENTITY_MUTATION",
  );
  requireCondition(
    before.observation?.phase === "preflight" &&
      after.observation?.phase === "postflight" &&
      before.observation.apiProvenanceVerified === false &&
      after.observation.apiProvenanceVerified === false &&
      before.observation.atomicSnapshotVerified === false &&
      after.observation.atomicSnapshotVerified === false &&
      before.observation.permissionScopeVerified === false &&
      after.observation.permissionScopeVerified === false &&
      before.observation.singleWriterVerified === false &&
      after.observation.singleWriterVerified === false &&
      before.observation.endpointSetSha256 === after.observation.endpointSetSha256 &&
      before.observation.controlPlanePairingSha256 ===
        after.observation.controlPlanePairingSha256 &&
      before.observation.tokenBindingSha256 ===
        after.observation.tokenBindingSha256 &&
      Date.parse(before.observation.lastObservedAt) <=
        Date.parse(after.observation.firstObservedAt),
    "REMOTE_OBSERVATION_PROVENANCE_REVIEW_REQUIRED",
  );
  requireCondition(
    isDeepStrictEqual(before.scriptSettings, after.scriptSettings),
    "UNEXPECTED_SCRIPT_SETTINGS_MUTATION",
  );
  requireCondition(
    isDeepStrictEqual(before.routes, after.routes) &&
      isDeepStrictEqual(before.customDomains, after.customDomains) &&
      isDeepStrictEqual(before.schedules, after.schedules) &&
      isDeepStrictEqual(before.queueConsumers, after.queueConsumers) &&
      isDeepStrictEqual(before.queueTriggers, after.queueTriggers),
    "UNEXPECTED_CONTROL_PLANE_MUTATION",
  );
  requireCondition(
    isDeepStrictEqual(before.deployments, after.deployments),
    "UNEXPECTED_ACTIVE_DEPLOYMENT_MUTATION",
  );
  requireCondition(
    isDeepStrictEqual(before.activeVersion, after.activeVersion),
    "UNEXPECTED_ACTIVE_VERSION_MUTATION",
  );
  const beforeVersions = versionMap(before.versions);
  const afterVersions = versionMap(after.versions);
  for (const [id, identity] of beforeVersions) {
    requireCondition(
      afterVersions.get(id) === identity,
      "FOREIGN_VERSION_INVENTORY_MUTATION",
    );
  }
  const added = [...afterVersions.keys()].filter((id) => !beforeVersions.has(id));
  requireCondition(
    added.length <= MAX_VERSION_CREATE_ATTEMPTS,
    "BOUNDED_RETRY_VERSION_LIMIT_EXCEEDED",
  );
  requireCondition(
    after.versions.length === before.versions.length + added.length &&
      isDeepStrictEqual(after.versions.slice(added.length), before.versions) &&
      isDeepStrictEqual(
        after.versions.slice(0, added.length).map(({ id }) => id),
        added,
      ),
    "FOREIGN_VERSION_INVENTORY_MUTATION",
  );
  if (added.length === 0) {
    requireCondition(outputRecord === null, "OUTPUT_VERSION_NOT_CREATED");
    requireCondition(
      isDeepStrictEqual(after.latestVersion, before.latestVersion),
      "FOREIGN_LATEST_VERSION_MUTATION",
    );
    return Object.freeze({
      status: "NO_MUTATION_RETRY_REQUIRES_OWNER",
      addedVersionIds: Object.freeze([]),
      duplicateInactiveVersionCount: 0,
      outputVersionId: null,
    });
  }

  requireCondition(
    added.length - 1 <= MAX_DUPLICATE_INACTIVE_VERSIONS,
    "BOUNDED_RETRY_DUPLICATE_LIMIT_EXCEEDED",
  );

  requireCondition(
    after.versions[0]?.id === added[0] &&
      after.latestVersion?.id === added[0],
    "EXPECTED_ADDED_VERSION_NOT_LATEST",
  );
  const activeIds = new Set(
    after.deployments.flatMap((deployment) =>
      deployment.versions.map((version) => version.version_id),
    ),
  );
  requireCondition(
    added.every((id) => !activeIds.has(id)),
    "ADDED_VERSION_BECAME_ACTIVE",
  );
  if (outputRecord !== null) {
    requireCondition(
      matchesPattern(outputRecord?.version_id, UUID_PATTERN) &&
        added.includes(outputRecord.version_id),
      "OUTPUT_VERSION_NOT_ADDED",
    );
  }
  const childSucceeded =
    childResult.status === 0 &&
    childResult.signal === null &&
    !childResult.timedOut &&
    !childResult.overflow;
  const outputMatchesLatest = outputRecord?.version_id === added[0];
  return Object.freeze({
    status:
      childSucceeded && outputMatchesLatest
        ? "VERIFIED_INACTIVE_VERSION"
        : "REVIEW_REQUIRED",
    addedVersionIds: Object.freeze([...added]),
    duplicateInactiveVersionCount: added.length - 1,
    outputVersionId: outputRecord?.version_id ?? null,
  });
}

export function buildWranglerChildEnvironment({
  sourceEnvironment,
  context,
  privateRoot,
  outputPath,
}) {
  const validated = validateProductionEnvironment(sourceEnvironment);
  requireCondition(
    validated.accountId === context.accountId &&
      validated.candidateSha === context.candidateSha &&
      validated.matchTag === context.matchTag,
    "CHILD_CONTEXT_MISMATCH",
  );
  return {
    CI: "true",
    WORKERS_CI: "1",
    WORKERS_CI_BRANCH: "main",
    WORKERS_CI_BUILD_UUID: sourceEnvironment.WORKERS_CI_BUILD_UUID,
    WORKERS_CI_COMMIT_SHA: context.candidateSha,
    CLOUDFLARE_API_TOKEN: sourceEnvironment.CLOUDFLARE_API_TOKEN,
    CLOUDFLARE_ACCOUNT_ID: context.accountId,
    CLOUDFLARE_COMPLIANCE_REGION: "public",
    CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV: "false",
    HOME: path.join(privateRoot, "home"),
    TEMP: path.join(privateRoot, "tmp"),
    TMP: path.join(privateRoot, "tmp"),
    TMPDIR: path.join(privateRoot, "tmp"),
    XDG_CACHE_HOME: path.join(privateRoot, "xdg-cache"),
    XDG_CONFIG_HOME: path.join(privateRoot, "xdg-config"),
    NO_COLOR: "1",
    WRANGLER_API_ENVIRONMENT: "production",
    WRANGLER_CACHE_DIR: path.join(privateRoot, "wrangler-cache"),
    WRANGLER_CI_GENERATE_PREVIEW_ALIAS: "false",
    WRANGLER_CI_MATCH_TAG: context.matchTag,
    WRANGLER_CI_OVERRIDE_NAME: PRODUCTION_WORKER_NAME,
    WRANGLER_LOG: "error",
    WRANGLER_LOG_PATH: path.join(privateRoot, "wrangler-logs"),
    WRANGLER_LOG_SANITIZE: "true",
    WRANGLER_OUTPUT_FILE_PATH: outputPath,
    WRANGLER_SEND_ERROR_REPORTS: "false",
    WRANGLER_SEND_METRICS: "false",
    WRANGLER_WRITE_LOGS: "false",
  };
}

export function wranglerUploadArguments({
  cliPath,
  privateConfigPath,
  candidateSha,
}) {
  requireCondition(
    matchesPattern(candidateSha, SHA_PATTERN) &&
      typeof cliPath === "string" &&
      path.isAbsolute(cliPath) &&
      path.basename(cliPath) === "cli.js" &&
      path.basename(path.dirname(cliPath)) === "wrangler-dist" &&
      typeof privateConfigPath === "string" &&
      path.isAbsolute(privateConfigPath),
    "UPLOAD_ARGUMENT_CONTRACT",
  );
  const message = `${UPLOAD_MESSAGE_PREFIX}${candidateSha}`;
  requireCondition(Buffer.byteLength(message, "utf8") <= 120, "UPLOAD_MESSAGE_SIZE");
  return {
    args: [
      "--no-warnings",
      cliPath,
      "versions",
      "upload",
      "--experimental-provision=false",
      "--experimental-auto-create=false",
      "--config",
      privateConfigPath,
      "--strict",
      "--tag",
      candidateSha,
      "--message",
      message,
    ],
    message,
  };
}

export function createFailClosedRemoteAdapter() {
  return Object.freeze({
    async readSnapshot() {
      fail("EXTERNAL_C_AND_OWNER_EXECUTION_REVIEW_REQUIRED");
    },
    async readVersion() {
      fail("EXTERNAL_C_AND_OWNER_EXECUTION_REVIEW_REQUIRED");
    },
  });
}

export async function withPrivateProductionUploadWorkspace({
  generatedConfig,
  generatedConfigPath,
  context,
  deps,
  inspect,
}) {
  requireCondition(typeof inspect === "function", "OFFLINE_INSPECTOR_REQUIRED");
  const privateConfig = derivePrivateProductionConfig(generatedConfig, context);
  requireCondition(
    isDeepStrictEqual(
      normalizePrivateProductionConfig(privateConfig, context),
      generatedConfig,
    ),
    "PRIVATE_CONFIG_NORMALIZATION",
  );

  const generatedDirectory = path.dirname(generatedConfigPath);
  const generatedDirectoryStat = deps.fs.lstatSync(generatedDirectory);
  requireCondition(
    generatedDirectoryStat.isDirectory() && !generatedDirectoryStat.isSymbolicLink(),
    "GENERATED_CONFIG_DIRECTORY",
  );
  const nonce = deps.randomBytes(16).toString("hex");
  const privateRoot = deps.fs.mkdtempSync(
    path.join(deps.tmpdir(), "pgid-production-version-upload-"),
  );
  deps.fs.chmodSync(privateRoot, 0o700);
  const privateConfigPath = path.join(
    generatedDirectory,
    `.pgid-production-${nonce}.json`,
  );
  const outputPath = path.join(privateRoot, "wrangler-output.jsonl");
  let configIdentity;
  let outputIdentity;
  try {
    configIdentity = writeExclusivePrivateFile(
      deps.fs,
      privateConfigPath,
      Buffer.from(`${JSON.stringify(privateConfig, null, 2)}\n`),
    );
    outputIdentity = writeExclusivePrivateFile(deps.fs, outputPath, Buffer.alloc(0));
    for (const directory of [
      "home",
      "tmp",
      "xdg-cache",
      "xdg-config",
      "wrangler-cache",
    ]) {
      const dirname = path.join(privateRoot, directory);
      deps.fs.mkdirSync(dirname, { mode: 0o700 });
      deps.fs.chmodSync(dirname, 0o700);
    }

    const result = await inspect({
      outputPath,
      privateConfig,
      privateConfigPath,
      privateRoot,
    });
    verifyPrivateFileIdentity(
      deps.fs,
      privateConfigPath,
      configIdentity,
      2 * 1024 * 1024,
      { unchanged: true },
    );
    verifyPrivateFileIdentity(
      deps.fs,
      outputPath,
      outputIdentity,
      WRANGLER_OUTPUT_MAX_BYTES,
    );
    return result;
  } finally {
    const cleanupSucceeded = [
      closePrivateIdentity(deps.fs, configIdentity),
      closePrivateIdentity(deps.fs, outputIdentity),
      removePrivatePath(deps.fs, privateConfigPath),
      removePrivatePath(deps.fs, privateRoot),
    ].every(Boolean);
    if (!cleanupSucceeded) fail("PRIVATE_CLEANUP_FAILED");
  }
}

export function evaluateOfflineProductionVersionUploadEvidence({
  before,
  after,
  outputBytes,
  childResult,
  details,
  context,
  ownerAcceptance,
  privateConfig,
  generatedConfig,
  startedAt,
  finishedAt,
  evaluatedAt,
}) {
  const acceptance = validateBoundedRetryOwnerAcceptance({
    acceptance: ownerAcceptance,
    context,
    evaluatedAt,
  });
  requireCondition(
    isDeepStrictEqual(
      privateConfig,
      derivePrivateProductionConfig(generatedConfig, context),
    ) &&
      isDeepStrictEqual(
        normalizePrivateProductionConfig(privateConfig, context),
        generatedConfig,
      ),
    "OFFLINE_CONFIG_CONTRACT",
  );
  validateNormalizedSnapshot(before, context);
  validateNormalizedSnapshot(after, context);
  validateUploadSnapshotTimeBracket({
    before,
    after,
    startedAt,
    finishedAt,
    evaluatedAt,
  });
  requireCondition(Buffer.isBuffer(outputBytes), "WRANGLER_OUTPUT_TYPE");
  const outputRecord =
    outputBytes.length === 0
      ? null
      : parseWranglerOutputJsonl(outputBytes, {
          matchTag: context.matchTag,
          startedAt,
          finishedAt,
        });
  const classification = classifyPostflight({
    before,
    after,
    outputRecord,
    childResult,
    startedAt,
    finishedAt,
    evaluatedAt,
  });
  requireCondition(Array.isArray(details), "UPLOADED_VERSION_DETAILS_SCHEMA");
  const detailById = new Map();
  for (const detail of details) {
    validateVersionDetail(detail);
    requireCondition(
      !detailById.has(detail.id),
      "UPLOADED_VERSION_DETAIL_DUPLICATE",
    );
    detailById.set(detail.id, detail);
  }
  requireCondition(
    details.length === classification.addedVersionIds.length &&
      classification.addedVersionIds.every((id) => detailById.has(id)),
    "UPLOADED_VERSION_DETAILS_INCOMPLETE",
  );

  let inventory = null;
  let observedScriptEtag = null;
  if (classification.addedVersionIds.length > 0) {
    requireCondition(
      isDeepStrictEqual(
        detailById.get(after.latestVersion.id),
        after.latestVersion,
      ),
      "UPLOADED_VERSION_DETAIL_MISMATCH",
    );
    observedScriptEtag = detailById.get(
      classification.addedVersionIds[0],
    ).scriptEtag;
    const message = `${UPLOAD_MESSAGE_PREFIX}${context.candidateSha}`;
    for (const versionId of classification.addedVersionIds) {
      const nextInventory = verifyUploadedVersion({
        detail: detailById.get(versionId),
        versionId,
        candidateSha: context.candidateSha,
        message,
        privateConfig,
        latestVersion: before.latestVersion,
        observedScriptEtag,
      });
      if (inventory === null) inventory = nextInventory;
      else {
        requireCondition(
          isDeepStrictEqual(nextInventory, inventory),
          "UPLOADED_RUNTIME_INVENTORY_INCONSISTENT",
        );
      }
    }
  }

  const observedScriptEtagSha256 =
    observedScriptEtag === null
      ? null
      : sha256(Buffer.from(observedScriptEtag));
  const ownerAcceptanceResolutionSha256 = sha256(
    Buffer.from(
      canonicalJson({
        acceptanceBindingSha256: acceptance.bindingSha256,
        resolvedObservedScriptEtagSha256: observedScriptEtagSha256,
      }),
    ),
  );

  return Object.freeze({
    schemaVersion: 2,
    evidenceMode: "OFFLINE_MODEL_ONLY",
    status: classification.status,
    productionExecutionBlocked: true,
    candidateSha: context.candidateSha,
    candidateTree: context.tree,
    buildCorrelationSha256: context.buildCorrelationSha256,
    targetBindingSha256: ownerAcceptance.targetBindingSha256,
    ownerAcceptanceResolutionSha256,
    addedVersionIds: classification.addedVersionIds,
    duplicateInactiveVersionCount:
      classification.duplicateInactiveVersionCount,
    reportedVersionId: classification.outputVersionId,
    verifiedVersionId:
      classification.status === "VERIFIED_INACTIVE_VERSION"
        ? classification.outputVersionId
        : null,
    generatedConfigSha256: sha256(Buffer.from(canonicalJson(generatedConfig))),
    runtimeInventorySha256:
      inventory === null
        ? null
        : sha256(Buffer.from(canonicalJson(inventory))),
    observedScriptEtagSha256,
    normalizedActiveDeploymentEqual: true,
    normalizedNonVersionedSettingsEqual: true,
    normalizedControlPlaneCollectionsEqual: true,
    normalizedAddedVersionsInactive: true,
    normalizedPreviewDisabled: true,
    paginationStructureClosed: true,
    remoteApiProvenanceVerified: false,
    remoteSnapshotAtomicityVerified: false,
    remotePermissionScopeVerified: false,
    remoteSingleWriterVerified: false,
    endpointSetSha256: before.observation.endpointSetSha256,
    controlPlanePairingSha256:
      before.observation.controlPlanePairingSha256,
    wrapperRetryAuthorized: false,
    pinnedToolInternalRetryAccepted: true,
    acceptedMaximumVersionCreateAttempts: MAX_VERSION_CREATE_ATTEMPTS,
    acceptedMaximumDuplicateInactiveVersions:
      MAX_DUPLICATE_INACTIVE_VERSIONS,
    assetIdentityVerified: false,
    scriptArtifactIdentityVerified: false,
    assetRetryResidual: ASSET_RETRY_RESIDUAL,
    scriptIdentityResidual: SCRIPT_IDENTITY_RESIDUAL,
    buildUuidAcceptanceResidual: BUILD_UUID_ACCEPTANCE_RESIDUAL,
  });
}

export async function runProductionVersionUploadGate() {
  requireCondition(
    PRODUCTION_EXECUTION_BLOCKERS.length === 0,
    "PRODUCTION_EXECUTION_REVIEW_REQUIRED",
  );
  fail("PRODUCTION_EXECUTION_ADAPTER_UNAVAILABLE");
}

async function main() {
  requireCondition(process.argv.length === 2, "CALLER_ARGUMENTS_FORBIDDEN");
  const receipt = await runProductionVersionUploadGate();
  console.log(JSON.stringify(receipt));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const code =
      error instanceof ProductionUploadGateError ? error.code : "INTERNAL_FAILURE";
    console.error(`Production version upload gate failed [${code}].`);
    process.exitCode = 1;
  });
}
