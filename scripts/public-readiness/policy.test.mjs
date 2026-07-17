import assert from "node:assert/strict";
import test from "node:test";

import {
  assertClosedInvocation,
  assertRemoteOperationsDenied,
  authorizeOwnedLocalOrigin,
  loadClosedProfile,
  publicReadinessPolicy,
  rejectCallerTarget,
} from "./policy.mjs";

test("authorizes only command-owned literal loopback origins and bounded profiles", () => {
  assert.equal(authorizeOwnedLocalOrigin("continuity"), "http://127.0.0.1:5183");
  assert.equal(authorizeOwnedLocalOrigin("drills"), "http://127.0.0.1:5185");
  assert.deepEqual(loadClosedProfile("drills"), {
    concurrency: 4,
    durationMs: 10000,
    requestsPerSecond: 12,
    totalRequests: 96,
  });
  assert.doesNotThrow(() => assertRemoteOperationsDenied());
});

test("rejects caller arguments and Cloudflare credentials before work starts", () => {
  for (const argv of [["--remote"], ["--target", "http://127.0.0.1:5183"], ["--preview"]]) {
    assert.throws(() => assertClosedInvocation(argv, {}));
  }
  assert.throws(() => assertClosedInvocation([], { CLOUDFLARE_API_TOKEN: "present" }));
  assert.doesNotThrow(() => assertClosedInvocation([], { PATH: "/usr/bin" }));
  assert.throws(() => rejectCallerTarget("http://127.0.0.1:5183"));
});

test("hard-denies DNS, localhost, Preview, and production even under policy mutation", () => {
  for (const origin of [
    "http://localhost:5183",
    "http://localtest.me:5183",
    "https://sso.pg72.tw",
    "https://preview.example.invalid",
  ]) {
    const policy = structuredClone(publicReadinessPolicy);
    policy.local.origins.continuity = origin;
    assert.throws(() => authorizeOwnedLocalOrigin("continuity", policy), undefined, origin);
  }

  const widened = structuredClone(publicReadinessPolicy);
  widened.production.restoreAllowed = true;
  assert.throws(() => assertRemoteOperationsDenied(widened), /must remain false/);
});

test("rejects unbounded or malformed local profiles", () => {
  const widened = structuredClone(publicReadinessPolicy);
  widened.local.profiles.drills.totalRequests = 201;
  assert.throws(() => loadClosedProfile("drills", widened), /exceeds its ceiling/);
  const malformed = structuredClone(publicReadinessPolicy);
  malformed.local.profiles.drills.concurrency = 0;
  assert.throws(() => loadClosedProfile("drills", malformed), /must be positive/);
});
