import assert from "node:assert/strict";

import { loadClosedProfile } from "./policy.mjs";

export const DRILL_DEFINITIONS = Object.freeze([
  Object.freeze({ expectedStatuses: [200], id: "health", path: "/health" }),
  Object.freeze({ expectedStatuses: [200], id: "readiness", path: "/ready" }),
  Object.freeze({
    expectedStatuses: [200],
    id: "discovery",
    path: "/.well-known/openid-configuration",
  }),
  Object.freeze({
    expectedStatuses: [400],
    id: "authorize_invalid",
    path: "/oauth2/authorize",
  }),
  Object.freeze({
    expectedStatuses: [401],
    id: "userinfo_unauthorized",
    path: "/oauth2/userinfo",
  }),
  Object.freeze({
    expectedStatuses: [401],
    id: "admin_unauthorized",
    path: "/api/admin/users",
  }),
]);

export const DRILL_SCENARIO_IDS = Object.freeze(
  DRILL_DEFINITIONS.map(({ id }) => id),
);
export const DRILL_PROFILE = Object.freeze(loadClosedProfile("drills"));

assert.equal(
  DRILL_PROFILE.totalRequests % DRILL_DEFINITIONS.length,
  0,
  "drill request budget must divide evenly across exact scenarios",
);

export const DRILL_REQUESTS_PER_SCENARIO =
  DRILL_PROFILE.totalRequests / DRILL_DEFINITIONS.length;
