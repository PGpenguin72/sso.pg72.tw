import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const policy = JSON.parse(
  readFileSync(new URL("../../security/dast-policy.json", import.meta.url), "utf8"),
);
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_BODY_BYTES = 128 * 1024;

function exactOrigin(value, name) {
  const url = new URL(value);
  assert.equal(url.origin, value, `${name} must be an exact origin without a path`);
  assert.equal(url.username, "", `${name} must not include credentials`);
  assert.equal(url.password, "", `${name} must not include credentials`);
  return url;
}

export function authorizeDastTarget(rawTarget, environment = process.env) {
  const target = exactOrigin(rawTarget || policy.local.defaultOrigin, "DAST target");
  assert.ok(!policy.forbiddenOrigins.includes(target.origin), "production PGID is never a DAST target");

  if (policy.local.allowedHostnames.includes(target.hostname)) {
    assert.equal(target.protocol, "http:", "local DAST must use loopback HTTP");
    return { mode: "local", origin: target.origin };
  }

  assert.equal(target.protocol, "https:", "Preview DAST requires HTTPS");
  assert.equal(target.port, "", "Preview DAST must use the default HTTPS port");
  assert.match(target.hostname, new RegExp(policy.preview.hostnamePattern), "target is not the isolated Preview Worker");
  assert.equal(
    environment.DAST_ALLOWED_PREVIEW_ORIGIN,
    target.origin,
    "target is not the protected environment allowlist value",
  );
  assert.equal(
    environment.DAST_PREVIEW_OPT_IN,
    policy.preview.optInValue,
    "owner Preview opt-in is missing",
  );
  return { mode: "preview", origin: target.origin };
}

async function readBody(response) {
  const length = Number(response.headers.get("content-length"));
  if (Number.isFinite(length)) assert.ok(length <= MAX_BODY_BYTES, "DAST response is unexpectedly large");
  const body = await response.text();
  assert.ok(Buffer.byteLength(body) <= MAX_BODY_BYTES, "DAST response exceeded the body limit");
  return body;
}

function securityHeaders(response) {
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.match(response.headers.get("strict-transport-security") ?? "", /^max-age=63072000/);
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  assert.match(response.headers.get("content-security-policy") ?? "", /object-src 'none'/);
  assert.match(response.headers.get("permissions-policy") ?? "", /publickey-credentials-get=\(self\)/);
}

async function probe(origin, definition) {
  const response = await fetch(new URL(definition.path, origin), {
    method: definition.method ?? "GET",
    headers: definition.headers,
    body: definition.body,
    redirect: "manual",
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const body = await readBody(response);
  securityHeaders(response);
  assert.ok(definition.statuses.includes(response.status), `${definition.name} returned ${response.status}: ${body}`);
  if (definition.cache === "no-store") {
    assert.match(response.headers.get("cache-control") ?? "", /(?:^|,)\s*no-store(?:,|$)/);
  } else if (definition.cache === "metadata") {
    assert.match(response.headers.get("cache-control") ?? "", /public, max-age=300/);
  }
  await definition.validate?.(response, body);
  return { name: definition.name, status: response.status };
}

function parseJson(body, name) {
  try {
    return JSON.parse(body);
  } catch {
    throw new Error(`${name} did not return JSON`);
  }
}

export async function scanPgid(origin) {
  const probes = [
    {
      name: "health",
      path: "/health",
      statuses: [200],
      validate: (_response, body) => {
        assert.deepEqual(parseJson(body, "health"), {
          status: "ok",
          service: "pg72-id",
          version: "0.1.0",
        });
      },
    },
    {
      name: "readiness",
      path: "/ready",
      statuses: [200],
      validate: (_response, body) => assert.equal(parseJson(body, "readiness").status, "ready"),
    },
    {
      name: "OIDC discovery",
      path: "/.well-known/openid-configuration",
      statuses: [200],
      cache: "metadata",
      validate: (_response, body) => {
        const metadata = parseJson(body, "discovery");
        assert.equal(metadata.issuer, origin);
        assert.deepEqual(metadata.response_types_supported, ["code"]);
        assert.ok(metadata.code_challenge_methods_supported.includes("S256"));
        assert.ok(!metadata.token_endpoint_auth_methods_supported.includes("client_secret_basic"));
        for (const field of [
          "authorization_endpoint",
          "token_endpoint",
          "jwks_uri",
          "userinfo_endpoint",
          "introspection_endpoint",
          "revocation_endpoint",
          "end_session_endpoint",
        ]) {
          assert.equal(new URL(metadata[field]).origin, origin, `${field} escaped the issuer origin`);
        }
      },
    },
    {
      name: "JWKS",
      path: "/.well-known/jwks.json",
      statuses: [200],
      cache: "metadata",
      validate: (_response, body) => {
        const jwks = parseJson(body, "JWKS");
        assert.ok(Array.isArray(jwks.keys) && jwks.keys.length > 0);
        for (const key of jwks.keys) {
          assert.equal(typeof key.kid, "string");
          for (const privateField of ["d", "p", "q", "dp", "dq", "qi", "k"]) {
            assert.equal(key[privateField], undefined, `JWKS exposed ${privateField}`);
          }
        }
      },
    },
    {
      name: "authorize missing parameters",
      path: "/oauth2/authorize",
      statuses: [400],
      cache: "no-store",
    },
    {
      name: "authorize resource rejection",
      path: "/oauth2/authorize?resource=https%3A%2F%2Fexample.invalid",
      statuses: [400],
      cache: "no-store",
      validate: (_response, body) => assert.equal(parseJson(body, "resource rejection").error, "invalid_target"),
    },
    {
      name: "token invalid request",
      path: "/oauth2/token",
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "",
      statuses: [400],
      cache: "no-store",
    },
    {
      name: "token resource rejection",
      path: "/oauth2/token",
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "resource=https%3A%2F%2Fexample.invalid",
      statuses: [400],
      cache: "no-store",
      validate: (_response, body) => assert.equal(parseJson(body, "token resource rejection").error, "invalid_target"),
    },
    {
      name: "userinfo without bearer",
      path: "/oauth2/userinfo",
      statuses: [401],
      cache: "no-store",
    },
    {
      name: "introspection without client credentials",
      path: "/oauth2/introspect",
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "",
      statuses: [400, 401],
      cache: "no-store",
    },
    {
      name: "revocation without client credentials",
      path: "/oauth2/revoke",
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "",
      statuses: [400, 401],
      cache: "no-store",
    },
    {
      name: "dynamic registration disabled",
      path: "/oauth2/register",
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
      statuses: [400, 401, 404, 405],
      cache: "no-store",
    },
    {
      name: "logout invalid request",
      path: "/oauth2/end-session",
      statuses: [302, 400],
      cache: "no-store",
      validate: (response) => {
        if (response.status === 302) assert.equal(new URL(response.headers.get("location"), origin).origin, origin);
      },
    },
    {
      name: "admin without session",
      path: "/api/admin/users",
      statuses: [401, 403],
      cache: "no-store",
    },
    {
      name: "cross-origin mutation rejection",
      path: "/passkey/update-passkey",
      method: "POST",
      headers: { origin: "https://attacker.invalid", "content-type": "application/json" },
      body: "{}",
      statuses: [403],
      cache: "no-store",
      validate: (_response, body) => assert.equal(parseJson(body, "CSRF rejection").error, "invalid_origin"),
    },
  ];

  const results = [];
  for (const definition of probes) results.push(await probe(origin, definition));
  return results;
}

export async function scanLocalRp(origin) {
  const health = await fetch(new URL("/health", origin), {
    redirect: "manual",
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  assert.equal(health.status, 200);
  assert.equal(parseJson(await readBody(health), "test RP health").service, "pg72-test-rp");

  const callback = await fetch(new URL("/callback", origin), {
    redirect: "manual",
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  assert.equal(callback.status, 400);
  const body = await readBody(callback);
  assert.match(body, /Missing OIDC transaction cookie/);
  return [
    { name: "test RP health", status: health.status },
    { name: "test RP callback error", status: callback.status },
  ];
}

function argument(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

async function main() {
  const authorized = authorizeDastTarget(argument("--target") ?? process.env.DAST_TARGET);
  if (process.argv.includes("--preview")) assert.equal(authorized.mode, "preview", "Preview mode requires an allowlisted Preview target");
  const results = await scanPgid(authorized.origin);
  console.log(`Safe ${authorized.mode} DAST passed (${results.length} PGID probes, no credentials).`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`DAST failed before completion: ${error.message}`);
    process.exitCode = 1;
  });
}
