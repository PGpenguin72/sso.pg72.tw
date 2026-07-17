import assert from "node:assert/strict";
import test from "node:test";

import {
  DRILL_DEFINITIONS,
  DRILL_PROFILE,
  DRILL_REQUESTS_PER_SCENARIO,
  DRILL_SCENARIO_IDS,
} from "./drill-contract.mjs";

test("pins the exact six-scenario bounded drill contract", () => {
  assert.deepEqual(DRILL_DEFINITIONS, [
    { expectedStatuses: [200], id: "health", path: "/health" },
    { expectedStatuses: [200], id: "readiness", path: "/ready" },
    {
      expectedStatuses: [200],
      id: "discovery",
      path: "/.well-known/openid-configuration",
    },
    {
      expectedStatuses: [400],
      id: "authorize_invalid",
      path: "/oauth2/authorize",
    },
    {
      expectedStatuses: [401],
      id: "userinfo_unauthorized",
      path: "/oauth2/userinfo",
    },
    {
      expectedStatuses: [401],
      id: "admin_unauthorized",
      path: "/api/admin/users",
    },
  ]);
  assert.deepEqual(DRILL_SCENARIO_IDS, [
    "health",
    "readiness",
    "discovery",
    "authorize_invalid",
    "userinfo_unauthorized",
    "admin_unauthorized",
  ]);
  assert.deepEqual(DRILL_PROFILE, {
    concurrency: 4,
    durationMs: 10_000,
    requestsPerSecond: 12,
    totalRequests: 96,
  });
  assert.equal(DRILL_REQUESTS_PER_SCENARIO, 16);
});
