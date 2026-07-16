import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { authorizeDastTarget, authorizePreviewRun, fetchOnce } from "./dast.mjs";

const policy = JSON.parse(
  readFileSync(new URL("../../security/dast-policy.json", import.meta.url), "utf8"),
);

function previewPolicy(origin = "https://pg72-id-preview.synthetic-preview.workers.dev") {
  const value = structuredClone(policy);
  value.preview.approvedOrigin = origin;
  return value;
}

function previewEnvironment(origin = "https://pg72-id-preview.synthetic-preview.workers.dev") {
  return {
    DAST_ALLOWED_PREVIEW_ORIGIN: origin,
    DAST_PREVIEW_OPT_IN: "owner-approved-isolated-preview",
    GITHUB_ACTOR: "PGpenguin72",
    GITHUB_TRIGGERING_ACTOR: "PGpenguin72",
    GITHUB_REF: "refs/heads/main",
  };
}

test("defaults to and accepts only canonical literal 127.0.0.1 origins on approved ports", () => {
  assert.deepEqual(authorizeDastTarget(undefined, {}, policy), {
    mode: "local",
    origin: "http://127.0.0.1:5173",
  });
  assert.deepEqual(authorizeDastTarget("http://127.0.0.1:5174", {}, policy), {
    mode: "local",
    origin: "http://127.0.0.1:5174",
  });
});

test("rejects localhost, DNS, IPv6, userinfo, paths, and unapproved local ports", () => {
  for (const target of [
    "http://localhost:5173",
    "http://localtest.me:5173",
    "http://[::1]:5173",
    "http://user:pass@127.0.0.1:5173",
    "http://127.0.0.1:5173/path",
    "http://127.0.0.1:5173?query=1",
    "http://127.0.0.1:5173/#fragment",
    "http://127.0.0.1:8787",
    "https://127.0.0.1:5173",
  ]) {
    assert.throws(() => authorizeDastTarget(target, {}, policy), undefined, target);
  }
});

test("hard-rejects production and fails closed while no Preview origin is approved", () => {
  assert.throws(
    () => authorizeDastTarget("https://sso.pg72.tw", previewEnvironment(), policy),
    /never a DAST target/,
  );
  const origin = "https://pg72-id-preview.synthetic-preview.workers.dev";
  assert.throws(
    () => authorizeDastTarget(origin, previewEnvironment(origin), policy),
    /no approved Preview origin/,
  );
});

test("requires exact repository Preview origin, protected opt-in, actor, rerun actor, and ref", () => {
  const origin = "https://pg72-id-preview.synthetic-preview.workers.dev";
  const activePolicy = previewPolicy(origin);
  const environment = previewEnvironment(origin);
  assert.deepEqual(authorizeDastTarget(origin, environment, activePolicy), {
    mode: "preview",
    origin,
  });

  for (const [key, value] of [
    ["DAST_ALLOWED_PREVIEW_ORIGIN", "https://pg72-id-preview.other.workers.dev"],
    ["DAST_PREVIEW_OPT_IN", "unapproved"],
    ["GITHUB_ACTOR", "attacker"],
    ["GITHUB_TRIGGERING_ACTOR", "attacker"],
    ["GITHUB_REF", "refs/heads/feature"],
  ]) {
    assert.throws(
      () => authorizeDastTarget(origin, { ...environment, [key]: value }, activePolicy),
      undefined,
      key,
    );
  }
  assert.doesNotThrow(() => authorizePreviewRun(environment, activePolicy));
});

test("rejects custom domains, pages.dev, wrong projects, and hostname lookalikes", () => {
  for (const origin of [
    "https://pg72-id-preview.example.com",
    "https://pg72-id-preview.pages.dev",
    "https://pg72-id-preview.evil.workers.dev.example.com",
    "https://pg72-id-preview-evil.synthetic-preview.workers.dev",
    "https://other.synthetic-preview.workers.dev",
  ]) {
    const activePolicy = previewPolicy(origin);
    assert.throws(
      () => authorizeDastTarget(origin, previewEnvironment(origin), activePolicy),
      /exact isolated Preview Worker project|project prefix/,
      origin,
    );
  }
});

test("manual request helper rejects Host overrides and never follows mocked redirects", async () => {
  const origin = "http://127.0.0.1:5173";
  let calls = 0;
  const mockFetch = async (target, init) => {
    calls += 1;
    assert.equal(target.href, `${origin}/health`);
    assert.equal(init.redirect, "manual");
    assert.equal(init.headers.has("host"), false);
    return new Response(null, {
      status: 302,
      headers: { location: "https://attacker.invalid/redirect" },
    });
  };
  const response = await fetchOnce(origin, "/health", {}, mockFetch);
  assert.equal(response.status, 302);
  assert.equal(calls, 1, "manual redirect unexpectedly caused another request");

  await assert.rejects(
    fetchOnce(origin, "/health", { headers: { host: "attacker.invalid" } }, mockFetch),
    /must not override host/,
  );
  await assert.rejects(
    fetchOnce(origin, "https://attacker.invalid/health", {}, mockFetch),
    /escaped its authorized origin/,
  );
  assert.equal(calls, 1);
});
