import assert from "node:assert/strict";
import test from "node:test";

import { dependencyStatus } from "./continuity-local.mjs";
import { readinessFromDependencies } from "./report.mjs";

test("machine readiness fails for absent recovery, observability, and archive source", () => {
  const dependencies = dependencyStatus();
  const byName = new Map(dependencies.map((entry) => [entry.name, entry.status]));
  assert.equal(byName.get("global_logout_0018"), "present");
  assert.equal(byName.get("recovery_0019"), "dependency_missing");
  assert.equal(byName.get("observability_0020"), "dependency_missing");
  assert.equal(byName.get("encrypted_r2_archive"), "dependency_missing");
  assert.deepEqual(readinessFromDependencies(dependencies), {
    ready: false,
    status: "blocked",
  });
});
