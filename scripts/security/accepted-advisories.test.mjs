import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { validateAcceptedAdvisories } from "./accepted-advisories.mjs";

const records = JSON.parse(
  readFileSync(new URL("../../security/accepted-advisories.json", import.meta.url), "utf8"),
);

function audit(overrides = {}) {
  const record = records.advisories[0];
  const advisory = {
    findings: [{ version: record.version, paths: ["apps__sso>@better-auth/oauth-provider"] }],
    title: record.title,
    module_name: record.package,
    vulnerable_versions: record.vulnerableVersions,
    patched_versions: record.patchedVersions,
    severity: record.severity,
    github_advisory_id: record.id,
    url: record.url,
    ...overrides,
  };
  return { advisories: { "1122767": advisory } };
}

const reviewDate = new Date("2026-07-17T00:00:00.000Z");

test("accepts only the exact recorded Moderate", () => {
  assert.deepEqual(validateAcceptedAdvisories(records, audit(), { now: reviewDate }), [
    "GHSA-p2fr-6hmx-4528",
  ]);
});

test("rejects an unrecorded advisory", () => {
  const changed = audit({ github_advisory_id: "GHSA-aaaa-bbbb-cccc" });
  assert.throws(
    () => validateAcceptedAdvisories(records, changed, { now: reviewDate }),
    /unrecorded/,
  );
});

test("rejects a changed package version", () => {
  const changed = audit();
  changed.advisories["1122767"].findings[0].version = "1.6.24";
  assert.throws(
    () => validateAcceptedAdvisories(records, changed, { now: reviewDate }),
    /installed version changed/,
  );
});

test("never accepts High or Critical findings", () => {
  assert.throws(
    () =>
      validateAcceptedAdvisories(records, audit({ severity: "high" }), {
        now: reviewDate,
      }),
    /cannot be waived/,
  );
});

test("rejects expired and indefinite waivers", () => {
  assert.throws(
    () =>
      validateAcceptedAdvisories(records, audit(), {
        now: new Date("2026-10-17T00:00:00.000Z"),
      }),
    /expired/,
  );

  const indefinite = structuredClone(records);
  indefinite.advisories[0].expiresOn = "2099-01-01";
  assert.throws(
    () => validateAcceptedAdvisories(indefinite, audit(), { now: reviewDate }),
    /exceeds 180 days/,
  );
});
