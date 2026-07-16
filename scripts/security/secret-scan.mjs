import assert from "node:assert/strict";
import { accessSync, constants, readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { redactedFindings, scanWorkingTree } from "./secret-family.mjs";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const tools = JSON.parse(
  readFileSync(new URL("../../security/tool-versions.json", import.meta.url), "utf8"),
);

function executable(candidate) {
  try {
    accessSync(candidate, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${path.basename(command)} exited ${result.status}`);
}

function runSecretlint() {
  const result = spawnSync(
    "pnpm",
    ["exec", "secretlint", "--secretlintrc", ".secretlintrc.json", "**/*"],
    { cwd: repoRoot, encoding: "utf8", maxBuffer: 20 * 1024 * 1024 },
  );
  if (result.error) throw result.error;
  assert.equal(
    result.status,
    0,
    "Secretlint reported working-tree findings; details are redacted by the release gate",
  );
}

function hasExpectedVersion(candidate) {
  const result = spawnSync(candidate, ["version"], { cwd: repoRoot, encoding: "utf8" });
  return result.status === 0 && result.stdout.trim() === tools.tools.gitleaks.version;
}

function main() {
  const configured = process.env.GITLEAKS_BIN;
  const local = path.join(repoRoot, ".security-tools", "gitleaks");
  let binary = null;
  for (const candidate of [configured, local].filter(Boolean)) {
    if (!executable(candidate)) continue;
    if (!hasExpectedVersion(candidate)) {
      throw new Error(`${candidate} does not match pinned Gitleaks ${tools.tools.gitleaks.version}`);
    }
    binary = candidate;
    break;
  }
  if (!binary) {
    const system = spawnSync("gitleaks", ["version"], { cwd: repoRoot, encoding: "utf8" });
    if (system.status === 0 && system.stdout.trim() === tools.tools.gitleaks.version) binary = "gitleaks";
  }
  assert.ok(
    binary,
    `pinned Gitleaks ${tools.tools.gitleaks.version} is required; run pnpm security:tools:install`,
  );
  run(binary, ["git", "--redact", "--no-banner", "--verbose", "--log-opts=--all", "."]);
  const findings = scanWorkingTree(repoRoot);
  assert.deepEqual(
    findings,
    [],
    `redacted working-tree findings:\n${redactedFindings(findings)}`,
  );
  runSecretlint();
  console.log(
    "Secret gate passed with Gitleaks full-history + redacted explicit/Secretlint working-tree scans.",
  );
}

try {
  main();
} catch (error) {
  console.error(`Secret gate failed: ${error.message}`);
  process.exitCode = 1;
}
