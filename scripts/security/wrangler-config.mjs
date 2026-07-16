import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Ajv from "ajv";
import { parse } from "jsonc-parser";

const policy = JSON.parse(
  readFileSync(new URL("../../security/release-policy.json", import.meta.url), "utf8"),
);

function sorted(values) {
  return [...values].sort();
}

function canonicalObject(value) {
  return Object.fromEntries(
    Object.entries(value ?? {}).sort(([left], [right]) => left.localeCompare(right)),
  );
}

function parseJsonc(url) {
  const errors = [];
  const value = parse(readFileSync(url, "utf8"), errors, {
    allowTrailingComma: true,
    disallowComments: false,
  });
  assert.deepEqual(errors, [], `${url.pathname} contains invalid JSONC`);
  return value;
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

function dateAgeDays(value, now = new Date()) {
  assert.match(value, /^\d{4}-\d{2}-\d{2}$/, "compatibility_date must be YYYY-MM-DD");
  return (now.getTime() - new Date(`${value}T00:00:00.000Z`).getTime()) / 86400000;
}

export function validateSsoConfig(config, now = new Date()) {
  const expected = policy.productionWorker;
  const errors = [];
  if (config.name !== expected.name) errors.push("unexpected production Worker name");
  if (config.main !== "worker/index.ts") errors.push("unexpected production entrypoint");
  if (!config.compatibility_flags?.includes("nodejs_compat")) errors.push("nodejs_compat is required");
  const age = dateAgeDays(config.compatibility_date, now);
  if (age < 0 || age > 180) errors.push("compatibility_date must be current within 180 days");
  if (
    config.routes?.length !== 1 ||
    config.routes[0]?.pattern !== expected.route ||
    config.routes[0]?.custom_domain !== true
  ) {
    errors.push("production route must be the exact PGID custom domain");
  }
  if (
    JSON.stringify(canonicalObject(config.vars)) !==
    JSON.stringify(canonicalObject(expected.vars))
  ) {
    errors.push("production vars drifted");
  }
  if (config.d1_databases?.length !== 1) errors.push("expected exactly one D1 binding");
  if (config.d1_databases?.[0]?.database_id !== "00000000-0000-0000-0000-000000000001") {
    errors.push("public source must retain the non-working D1 placeholder");
  }
  if (!config.assets || config.assets.binding !== "ASSETS" || config.assets.run_worker_first !== true) {
    errors.push("production static-assets binding drifted");
  }
  if (config.queues?.consumers?.length !== 1 || config.queues?.producers?.length !== 1) {
    errors.push("security Queue bindings drifted");
  }
  if (
    JSON.stringify(sorted(config.d1_databases?.map((binding) => binding.binding) ?? [])) !==
    JSON.stringify(sorted(expected.d1Bindings))
  ) {
    errors.push("D1 binding names drifted");
  }
  if (
    JSON.stringify(sorted(config.queues?.producers?.map((binding) => binding.binding) ?? [])) !==
    JSON.stringify(sorted(expected.queueBindings))
  ) {
    errors.push("Queue binding names drifted");
  }
  if (
    JSON.stringify(sorted(config.ratelimits?.map((binding) => binding.name) ?? [])) !==
    JSON.stringify(sorted(expected.rateLimitBindings))
  ) {
    errors.push("Rate Limit binding names drifted");
  }
  if (
    JSON.stringify(sorted(config.secrets?.required ?? [])) !==
    JSON.stringify(sorted(expected.requiredSecrets))
  ) {
    errors.push("required secret names drifted");
  }
  for (const key of Object.keys(config.vars ?? {})) {
    if (/(?:SECRET|PASSWORD|PRIVATE_KEY|API_TOKEN)/.test(key)) errors.push(`secret-like var ${key}`);
  }
  errors.push(...remoteBindingPaths(config).map((entry) => `remote binding forbidden: ${entry}`));
  if (config.account_id !== undefined) errors.push("account_id must not be committed");
  return errors;
}

export function validateTestRpConfig(config, now = new Date()) {
  const errors = [];
  if (config.name !== "pg72-oidc-test-rp") errors.push("unexpected test RP name");
  if (config.main !== "worker/index.ts") errors.push("unexpected test RP entrypoint");
  if (!config.compatibility_flags?.includes("nodejs_compat")) errors.push("test RP needs nodejs_compat");
  const age = dateAgeDays(config.compatibility_date, now);
  if (age < 0 || age > 180) errors.push("test RP compatibility_date must be current within 180 days");
  if (config.routes !== undefined || config.workers_dev === true) errors.push("test RP must not expose a remote route");
  if (config.vars?.ENVIRONMENT !== "development") errors.push("test RP must remain development-only");
  for (const key of ["OIDC_ISSUER", "RP_BASE_URL"]) {
    const url = new URL(config.vars?.[key]);
    if (url.protocol !== "http:" || url.hostname !== "localhost") errors.push(`${key} must be localhost HTTP`);
  }
  errors.push(...remoteBindingPaths(config).map((entry) => `remote binding forbidden: ${entry}`));
  return errors;
}

function main() {
  const ssoUrl = new URL("../../apps/sso/wrangler.jsonc", import.meta.url);
  const rpUrl = new URL("../../apps/test-rp/wrangler.jsonc", import.meta.url);
  const sso = parseJsonc(ssoUrl);
  const rp = parseJsonc(rpUrl);
  const schema = JSON.parse(
    readFileSync(new URL("../../apps/sso/node_modules/wrangler/config-schema.json", import.meta.url), "utf8"),
  );
  const ajv = new Ajv({ allErrors: true, strict: false, validateFormats: false });
  const validate = ajv.compile(schema);
  const errors = [];
  for (const [name, value] of [["apps/sso", sso], ["apps/test-rp", rp]]) {
    if (!validate(value)) {
      errors.push(`${name}: ${ajv.errorsText(validate.errors, { separator: "\n" })}`);
    }
  }
  errors.push(...validateSsoConfig(sso).map((error) => `apps/sso: ${error}`));
  errors.push(...validateTestRpConfig(rp).map((error) => `apps/test-rp: ${error}`));
  assert.deepEqual(errors, [], errors.join("\n"));
  console.log("Wrangler schema and binding gate passed (production Worker + local test RP).");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`Wrangler config gate failed: ${error.message}`);
    process.exitCode = 1;
  }
}
