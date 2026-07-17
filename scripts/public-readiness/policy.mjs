import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

export const publicReadinessPolicy = JSON.parse(
  readFileSync(
    new URL("../../security/public-readiness-policy.json", import.meta.url),
    "utf8",
  ),
);

const LOCAL_ORIGIN_PATTERN = /^http:\/\/127\.0\.0\.1:(\d{2,5})$/;
const FORBIDDEN_ARGUMENTS = new Set([
  "--env",
  "--origin",
  "--preview",
  "--remote",
  "--target",
  "--url",
]);
const CLOUD_CREDENTIAL_NAMES = new Set([
  "CF_API_KEY",
  "CF_API_TOKEN",
  "CLOUDFLARE_ACCOUNT_ID",
  "CLOUDFLARE_API_KEY",
  "CLOUDFLARE_API_TOKEN",
  "WRANGLER_API_TOKEN",
  "WRANGLER_OAUTH_TOKEN",
]);

function exactOrigin(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  const parsed = new URL(value);
  assert.equal(parsed.origin, value, `${label} must be an exact origin`);
  assert.equal(parsed.username, "", `${label} must not include credentials`);
  assert.equal(parsed.password, "", `${label} must not include credentials`);
  return parsed;
}

export function assertClosedInvocation(
  argv = process.argv.slice(2),
  environment = process.env,
) {
  assert.deepEqual(argv, [], "public-readiness commands do not accept arguments");
  for (const argument of argv) {
    const name = argument.split("=", 1)[0];
    assert.ok(!FORBIDDEN_ARGUMENTS.has(name), `${name} is forbidden`);
  }
  for (const name of CLOUD_CREDENTIAL_NAMES) {
    assert.ok(
      !environment[name],
      `${name} must be absent for source-local public-readiness commands`,
    );
  }
}

export function authorizeOwnedLocalOrigin(
  operation,
  activePolicy = publicReadinessPolicy,
) {
  assert.ok(
    operation === "continuity" || operation === "drills",
    "unknown public-readiness operation",
  );
  const value = activePolicy.local?.origins?.[operation];
  const origin = exactOrigin(value, `${operation} origin`);
  assert.match(
    value,
    LOCAL_ORIGIN_PATTERN,
    `${operation} requires a literal 127.0.0.1 origin and fixed port`,
  );
  assert.equal(origin.protocol, "http:");
  assert.ok(
    !activePolicy.forbiddenOrigins.includes(origin.origin),
    "production PGID is never a public-readiness target",
  );
  assert.notEqual(
    origin.origin,
    "https://sso.pg72.tw",
    "production PGID is unconditionally denied",
  );
  return origin.origin;
}

function positiveInteger(value, label) {
  assert.ok(Number.isSafeInteger(value) && value > 0, `${label} must be positive`);
  return value;
}

export function loadClosedProfile(
  operation,
  activePolicy = publicReadinessPolicy,
) {
  authorizeOwnedLocalOrigin(operation, activePolicy);
  const profile = activePolicy.local?.profiles?.[operation];
  const ceilings = activePolicy.local?.absoluteCeilings;
  assert.ok(profile && ceilings, "local profile policy is incomplete");
  const result = {};
  for (const name of [
    "concurrency",
    "durationMs",
    "requestsPerSecond",
    "totalRequests",
  ]) {
    result[name] = positiveInteger(profile[name], `${operation}.${name}`);
    const ceiling = positiveInteger(ceilings[name], `ceiling.${name}`);
    assert.ok(result[name] <= ceiling, `${operation}.${name} exceeds its ceiling`);
  }
  return Object.freeze(result);
}

export function assertRemoteOperationsDenied(activePolicy = publicReadinessPolicy) {
  assert.equal(activePolicy.preview?.approvedOrigin, null);
  assert.equal(activePolicy.preview?.budgets, null);
  for (const field of [
    "deployAllowed",
    "faultInjectionAllowed",
    "loadAllowed",
    "restoreAllowed",
  ]) {
    assert.equal(
      activePolicy.production?.[field],
      false,
      `production ${field} must remain false`,
    );
  }
  assert.equal(
    activePolicy.production?.origin,
    "https://sso.pg72.tw",
    "production deny must name the canonical issuer",
  );
}

export function rejectCallerTarget(value) {
  assert.equal(
    value,
    undefined,
    "public-readiness commands own their target; caller targets are forbidden",
  );
}
