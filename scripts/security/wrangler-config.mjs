import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";
import Ajv from "ajv";
import { parse } from "jsonc-parser";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
export const releasePolicy = JSON.parse(
  readFileSync(new URL("../../security/release-policy.json", import.meta.url), "utf8"),
);

function parseJsonc(filename) {
  const errors = [];
  const value = parse(readFileSync(filename, "utf8"), errors, {
    allowTrailingComma: true,
    disallowComments: false,
  });
  assert.deepEqual(errors, [], `${filename} contains invalid JSONC`);
  return value;
}

function dateAgeDays(value, now = new Date()) {
  assert.match(value, /^\d{4}-\d{2}-\d{2}$/, "compatibility_date must be YYYY-MM-DD");
  return (now.getTime() - new Date(`${value}T00:00:00.000Z`).getTime()) / 86400000;
}

function policyErrors(environment) {
  const errors = [];
  const worker = environment.worker;
  for (const entry of worker.vars) {
    if (entry.type !== "plain-var") errors.push(`plain var ${entry.name} has the wrong type`);
  }
  for (const entry of worker.secrets) {
    if (entry.type !== "secret") errors.push(`secret ${entry.name} has the wrong type`);
  }
  for (const entry of worker.d1) {
    if (entry.type !== "d1") errors.push(`D1 ${entry.name} has the wrong type`);
    if (entry.target.databaseId.contract !== "reviewed-nonworking-placeholder") {
      errors.push(`D1 ${entry.name} lacks the reviewed placeholder contract`);
    }
    if (!/^00000000-0000-0000-0000-00000000000[1-9]$/.test(entry.target.databaseId.value)) {
      errors.push(`D1 ${entry.name} must use a visibly non-working UUID placeholder`);
    }
  }
  for (const entry of worker.queues.producers) {
    if (entry.type !== "queue-producer") errors.push(`Queue producer ${entry.name} has the wrong type`);
  }
  for (const entry of worker.queues.consumers) {
    if (entry.type !== "queue-consumer") errors.push(`Queue consumer ${entry.name} has the wrong type`);
  }
  for (const entry of worker.rateLimits) {
    if (entry.type !== "rate-limit") errors.push(`Rate Limit ${entry.name} has the wrong type`);
  }
  if (worker.assets && worker.assets.type !== "assets") {
    errors.push(`Assets ${worker.assets.name} has the wrong type`);
  }
  for (const route of worker.routes) {
    if (route.type !== "custom-domain") errors.push(`route ${route.pattern} has the wrong type`);
  }
  return errors;
}

function varsObject(records) {
  return Object.fromEntries(records.map(({ name, value }) => [name, value]));
}

function sourceD1(records) {
  return records.map((entry) => ({
    binding: entry.name,
    database_name: entry.target.databaseName,
    database_id: entry.target.databaseId.value,
    migrations_dir: entry.target.sourceMigrationsDirectory,
  }));
}

function generatedD1(records) {
  return records.map((entry) => ({
    binding: entry.name,
    database_name: entry.target.databaseName,
    database_id: entry.target.databaseId.value,
    migrations_dir: entry.target.generatedMigrationsDirectory,
  }));
}

function sourceQueues(queues) {
  return {
    producers: queues.producers.map((entry) => ({ binding: entry.name, queue: entry.target })),
    consumers: queues.consumers.map((entry) => ({
      queue: entry.target,
      max_batch_size: entry.maxBatchSize,
      max_batch_timeout: entry.maxBatchTimeout,
      max_retries: entry.maxRetries,
      dead_letter_queue: entry.deadLetterTarget,
    })),
  };
}

function sourceRateLimits(records) {
  return records.map((entry) => ({
    name: entry.name,
    namespace_id: entry.target,
    simple: { limit: entry.limit, period: entry.period },
  }));
}

function sourceRoutes(records) {
  return records.map((entry) => ({ pattern: entry.pattern, custom_domain: entry.customDomain }));
}

function sourceAssets(entry) {
  return {
    binding: entry.name,
    not_found_handling: entry.notFoundHandling,
    run_worker_first: entry.runWorkerFirst,
  };
}

function generatedAssets(entry) {
  return { ...sourceAssets(entry), directory: entry.generatedDirectory };
}

export function expectedSourceConfig(environment) {
  const worker = environment.worker;
  const expected = {
    $schema: "node_modules/wrangler/config-schema.json",
    name: worker.name,
    main: worker.main.source,
    compatibility_date: worker.compatibilityDate,
    compatibility_flags: worker.compatibilityFlags,
  };
  if (worker.routes.length > 0) expected.routes = sourceRoutes(worker.routes);
  if (worker.assets) expected.assets = sourceAssets(worker.assets);
  if (worker.d1.length > 0) expected.d1_databases = sourceD1(worker.d1);
  if (worker.rateLimits.length > 0) expected.ratelimits = sourceRateLimits(worker.rateLimits);
  if (worker.queues.producers.length > 0 || worker.queues.consumers.length > 0) {
    expected.queues = sourceQueues(worker.queues);
  }
  expected.vars = varsObject(worker.vars);
  if (worker.secrets.length > 0) expected.secrets = { required: worker.secrets.map(({ name }) => name) };
  expected.observability = worker.observability;
  return expected;
}

function compareExact(actual, expected, label) {
  const errors = [];
  for (const key of new Set([...Object.keys(actual), ...Object.keys(expected)])) {
    if (!isDeepStrictEqual(actual[key], expected[key])) errors.push(`${label}.${key} drifted`);
  }
  return errors;
}

function remoteBindingPaths(value, prefix = "") {
  const failures = [];
  if (!value || typeof value !== "object") return failures;
  for (const [key, child] of Object.entries(value)) {
    const next = prefix ? `${prefix}.${key}` : key;
    if (key === "remote" && child === true) failures.push(next);
    failures.push(...remoteBindingPaths(child, next));
  }
  return failures;
}

export function validateEnvironmentSource(config, environment, now = new Date()) {
  const errors = policyErrors(environment);
  errors.push(...compareExact(config, expectedSourceConfig(environment), "source"));
  const age = dateAgeDays(config.compatibility_date, now);
  if (age < 0 || age > 180) errors.push("compatibility_date must be current within 180 days");
  errors.push(...remoteBindingPaths(config).map((entry) => `remote binding forbidden: ${entry}`));
  if (config.account_id !== undefined) errors.push("account_id must not be committed");
  return errors;
}

export function validateSsoConfig(config, now = new Date()) {
  return validateEnvironmentSource(config, releasePolicy.environments.production, now);
}

export function validateTestRpConfig(config, now = new Date()) {
  return validateEnvironmentSource(config, releasePolicy.environments.localTestRp, now);
}

export function expectedGeneratedSsoConfig(root = repoRoot) {
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
    routes: sourceRoutes(worker.routes),
    triggers: {},
    assets: generatedAssets(worker.assets),
    vars: varsObject(worker.vars),
    secrets: { required: worker.secrets.map(({ name }) => name) },
    durable_objects: { bindings: [] },
    workflows: [],
    migrations: [],
    exports: {},
    kv_namespaces: [],
    cloudchamber: {},
    send_email: [],
    queues: sourceQueues(worker.queues),
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
    ratelimits: sourceRateLimits(worker.rateLimits),
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

export function validateGeneratedSsoConfig(config, root = repoRoot) {
  const environment = releasePolicy.environments.production;
  const errors = policyErrors(environment);
  errors.push(...compareExact(config, expectedGeneratedSsoConfig(root), "generated"));
  errors.push(...remoteBindingPaths(config).map((entry) => `generated remote binding forbidden: ${entry}`));
  if (config.account_id !== undefined) errors.push("generated account_id must not be present");
  return errors;
}

function main() {
  assert.equal(releasePolicy.schemaVersion, 2, "release policy schemaVersion must be 2");
  const schema = JSON.parse(
    readFileSync(path.join(repoRoot, "apps/sso/node_modules/wrangler/config-schema.json"), "utf8"),
  );
  const ajv = new Ajv({ allErrors: true, strict: false, validateFormats: false });
  const validateSchema = ajv.compile(schema);
  const errors = [];
  for (const [name, environment, validator] of [
    ["production", releasePolicy.environments.production, validateSsoConfig],
    ["localTestRp", releasePolicy.environments.localTestRp, validateTestRpConfig],
  ]) {
    const filename = path.join(repoRoot, environment.sourceConfig);
    const config = parseJsonc(filename);
    if (!validateSchema(config)) {
      errors.push(`${name}: ${ajv.errorsText(validateSchema.errors, { separator: "\n" })}`);
    }
    errors.push(...validator(config).map((error) => `${name}: ${error}`));
  }
  const generatedPath = path.join(
    repoRoot,
    releasePolicy.environments.production.generatedConfig,
  );
  if (!existsSync(generatedPath)) {
    errors.push("production: generated config is missing; run pnpm --filter @pg72/id build");
  } else {
    const generated = JSON.parse(readFileSync(generatedPath, "utf8"));
    errors.push(
      ...validateGeneratedSsoConfig(generated).map((error) => `production artifact: ${error}`),
    );
  }
  assert.deepEqual(errors, [], errors.join("\n"));
  console.log("Wrangler source/generated binding contracts passed (production + local test RP).");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`Wrangler config gate failed: ${error.message}`);
    process.exitCode = 1;
  }
}
