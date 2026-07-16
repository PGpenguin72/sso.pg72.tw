import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const recordPath = new URL("../../security/accepted-advisories.json", import.meta.url);
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_ACCEPTANCE_DAYS = 180;
const severityOrder = new Map([
  ["info", 0],
  ["low", 1],
  ["moderate", 2],
  ["high", 3],
  ["critical", 4],
]);

function parseDate(value, field) {
  assert.match(value, /^\d{4}-\d{2}-\d{2}$/, `${field} must be YYYY-MM-DD`);
  const date = new Date(`${value}T00:00:00.000Z`);
  assert.equal(date.toISOString().slice(0, 10), value, `${field} is invalid`);
  return date;
}

function validateRecord(record, now) {
  assert.match(record.id, /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/);
  assert.match(record.package, /^(?:@[^/]+\/)?[^/]+$/);
  assert.match(record.version, /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/);
  assert.equal(record.severity, "moderate", `${record.id} is not an accepted Moderate`);
  assert.equal(record.reviewCommand, "pnpm audit --json");
  assert.ok(record.title.length >= 20, `${record.id} needs the advisory title`);
  assert.ok(record.rationale.length >= 40, `${record.id} needs a specific rationale`);
  assert.ok(record.owner.length >= 3, `${record.id} needs an owner`);
  assert.ok(
    Array.isArray(record.compensatingControls) &&
      record.compensatingControls.length >= 2 &&
      record.compensatingControls.every((control) => control.length >= 20),
    `${record.id} needs at least two concrete compensating controls`,
  );

  const accepted = parseDate(record.acceptedOn, `${record.id}.acceptedOn`);
  const expiry = parseDate(record.expiresOn, `${record.id}.expiresOn`);
  assert.ok(expiry > accepted, `${record.id} expiry must follow acceptance`);
  assert.ok(
    (expiry.getTime() - accepted.getTime()) / DAY_MS <= MAX_ACCEPTANCE_DAYS,
    `${record.id} waiver exceeds ${MAX_ACCEPTANCE_DAYS} days`,
  );
  assert.ok(now <= expiry, `${record.id} acceptance expired on ${record.expiresOn}`);

  const manifestUrl = new URL(`../../${record.packageManifest}`, import.meta.url);
  const manifest = JSON.parse(readFileSync(manifestUrl, "utf8"));
  const pinned = manifest.dependencies?.[record.package] ?? manifest.devDependencies?.[record.package];
  assert.equal(
    pinned,
    record.version,
    `${record.id} package/version no longer matches ${record.packageManifest}`,
  );
}

export function validateAcceptedAdvisories(recordsFile, audit, options = {}) {
  assert.equal(recordsFile.schemaVersion, 1, "unsupported advisory record schema");
  assert.ok(Array.isArray(recordsFile.advisories), "advisories must be an array");
  assert.ok(audit && typeof audit.advisories === "object", "invalid pnpm audit JSON");

  const now = options.now ?? new Date();
  const records = new Map();
  for (const record of recordsFile.advisories) {
    validateRecord(record, now);
    assert.ok(!records.has(record.id), `duplicate accepted advisory ${record.id}`);
    records.set(record.id, record);
  }

  const observed = new Set();
  for (const advisory of Object.values(audit.advisories)) {
    const id = advisory.github_advisory_id;
    assert.match(id ?? "", /^GHSA-/, "audit advisory is missing a GHSA id");
    const rank = severityOrder.get(advisory.severity);
    assert.notEqual(rank, undefined, `${id} has unknown severity ${advisory.severity}`);
    assert.ok(rank < severityOrder.get("high"), `${id} is ${advisory.severity} and cannot be waived`);

    const record = records.get(id);
    assert.ok(record, `${id} is unrecorded`);
    observed.add(id);
    assert.equal(advisory.module_name, record.package, `${id} package changed`);
    assert.equal(advisory.severity, record.severity, `${id} severity changed`);
    assert.equal(advisory.title, record.title, `${id} title changed`);
    assert.equal(advisory.vulnerable_versions, record.vulnerableVersions, `${id} range changed`);
    assert.equal(advisory.patched_versions, record.patchedVersions, `${id} patched range changed`);
    assert.equal(advisory.url, record.url, `${id} URL changed`);

    const versions = [
      ...new Set(
        advisory.findings.flatMap((finding) =>
          typeof finding.version === "string" ? [finding.version] : [],
        ),
      ),
    ].sort();
    assert.deepEqual(versions, [record.version], `${id} installed version changed`);
  }

  for (const id of records.keys()) {
    assert.ok(observed.has(id), `${id} is a stale waiver not present in the audit`);
  }
  return [...observed].sort();
}

function runAudit() {
  const result = spawnSync("pnpm", ["audit", "--json"], {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && result.status !== 1) {
    throw new Error(`pnpm audit failed (${result.status}): ${result.stderr.trim()}`);
  }
  return JSON.parse(result.stdout);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const records = JSON.parse(readFileSync(recordPath, "utf8"));
    const accepted = validateAcceptedAdvisories(records, runAudit());
    console.log(`Dependency advisory gate passed; accepted Moderate: ${accepted.join(", ")}.`);
  } catch (error) {
    console.error(`Dependency advisory gate failed: ${error.message}`);
    process.exitCode = 1;
  }
}
