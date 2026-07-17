import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { dependencyStatus } from "./continuity-local.mjs";
import { readinessFromDependencies } from "./report.mjs";

test("machine readiness fails for absent recovery, observability, and archive source", () => {
  const repositoryRoot = mkdtempSync(
    path.join(os.tmpdir(), "pgid-missing-readiness-dependencies-"),
  );
  const identityRoot = path.join(repositoryRoot, "apps", "sso");
  try {
    for (const directory of [
      path.join(identityRoot, "migrations"),
      path.join(identityRoot, "worker"),
      path.join(repositoryRoot, "security"),
      path.join(repositoryRoot, "scripts", "security"),
    ]) {
      mkdirSync(directory, { recursive: true });
    }
    writeFileSync(path.join(identityRoot, "wrangler.jsonc"), "{}\n");
    writeFileSync(
      path.join(identityRoot, "migrations", "0018_global_logout.sql"),
      "-- source-presence fixture\n",
    );
    writeFileSync(
      path.join(repositoryRoot, "security", "release-policy.json"),
      "{}\n",
    );
    writeFileSync(
      path.join(repositoryRoot, "scripts", "security", "dast.mjs"),
      "// source-presence fixture\n",
    );
    const dependencies = dependencyStatus({ identityRoot, repositoryRoot });
    const byName = new Map(
      dependencies.map((entry) => [entry.name, entry.status]),
    );
    assert.equal(byName.get("global_logout_0018"), "present");
    assert.equal(byName.get("recovery_0019"), "dependency_missing");
    assert.equal(byName.get("observability_0020"), "dependency_missing");
    assert.equal(byName.get("encrypted_r2_archive"), "dependency_missing");
    assert.equal(byName.get("release_automation"), "present");
    assert.deepEqual(readinessFromDependencies(dependencies), {
      ready: false,
      status: "blocked",
    });
  } finally {
    rmSync(repositoryRoot, { force: true, recursive: true });
  }
});
