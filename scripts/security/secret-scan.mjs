import { accessSync, constants, readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

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
  if (binary) {
    run(binary, ["git", "--redact", "--no-banner", "--verbose", "--log-opts=--all", "."]);
    console.log("Gitleaks history scan passed; checking the current working tree with Secretlint.");
  } else {
    console.log("Gitleaks is unavailable; using the pinned Secretlint working-tree fallback.");
  }
  run("pnpm", ["exec", "secretlint", "--secretlintrc", ".secretlintrc.json", "**/*"]);
  console.log(
    binary
      ? "Secret gate passed with Gitleaks history + Secretlint working-tree scans."
      : "Secret gate passed with Secretlint fallback.",
  );
}

try {
  main();
} catch (error) {
  console.error(`Secret gate failed: ${error.message}`);
  process.exitCode = 1;
}
