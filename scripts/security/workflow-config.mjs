import assert from "node:assert/strict";
import { accessSync, constants, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const workflowDirectory = path.join(repoRoot, ".github", "workflows");
const tools = JSON.parse(
  readFileSync(new URL("../../security/tool-versions.json", import.meta.url), "utf8"),
);

function entries(value) {
  return value && typeof value === "object" ? Object.entries(value) : [];
}

export function validateWorkflowDocument(document, filename, toolVersions = tools) {
  const errors = [];
  const triggers = document.on;
  if (!triggers || typeof triggers !== "object") errors.push("on must be a mapping");
  if (triggers?.pull_request_target !== undefined) errors.push("pull_request_target is forbidden");

  const permissionKeys = entries(document.permissions).map(([key]) => key);
  if (
    permissionKeys.length !== 1 ||
    permissionKeys[0] !== "contents" ||
    document.permissions.contents !== "read"
  ) {
    errors.push("top-level permissions must be exactly contents: read");
  }
  if (!document.concurrency?.group || document.concurrency?.["cancel-in-progress"] !== true) {
    errors.push("concurrency must define a group and cancel-in-progress: true");
  }

  for (const [jobName, job] of entries(document.jobs)) {
    if (!Number.isInteger(job["timeout-minutes"]) || job["timeout-minutes"] <= 0) {
      errors.push(`${jobName} must have a positive timeout-minutes`);
    }
    if (job.permissions !== undefined) errors.push(`${jobName} must not elevate permissions`);
    if (!Array.isArray(job.steps)) errors.push(`${jobName} steps must be an array`);

    for (const [index, step] of (job.steps ?? []).entries()) {
      const label = `${jobName}.steps[${index}]`;
      if (typeof step.uses === "string" && !step.uses.startsWith("./")) {
        const match = /^([^@]+)@([0-9a-f]{40})$/.exec(step.uses);
        if (!match) {
          errors.push(`${label} action must use an immutable 40-character SHA`);
        } else {
          const pinned = toolVersions.actions[match[1]];
          if (!pinned) errors.push(`${label} action ${match[1]} is not in security/tool-versions.json`);
          else if (pinned.sha !== match[2]) errors.push(`${label} action SHA does not match ${pinned.version}`);
        }
      }
      if (step.uses?.startsWith("actions/checkout@") && step.with?.["persist-credentials"] !== false) {
        errors.push(`${label} checkout must set persist-credentials: false`);
      }
      if (step.uses?.startsWith("actions/upload-artifact@")) {
        const retention = Number(step.with?.["retention-days"]);
        if (!Number.isInteger(retention) || retention < 1 || retention > 7) {
          errors.push(`${label} artifact retention must be 1-7 days`);
        }
      }
      if (typeof step.run === "string") {
        if (/\bwrangler\b[^\n]*(?:--remote|\bd1\b[^\n]*\bremote\b)/i.test(step.run)) {
          errors.push(`${label} contains a remote Wrangler command`);
        }
        if (/\bwrangler\s+(?:deploy|versions\s+upload)\b/i.test(step.run) && !/--dry-run\b/.test(step.run)) {
          errors.push(`${label} contains a non-dry-run deployment command`);
        }
      }
    }
  }

  if (path.basename(filename) === "dast-preview.yml") {
    if (Object.keys(triggers ?? {}).join(",") !== "workflow_dispatch") {
      errors.push("Preview DAST must be workflow_dispatch only");
    }
    for (const [jobName, job] of entries(document.jobs)) {
      if (job.environment !== "isolated-preview") {
        errors.push(`${jobName} must use the protected isolated-preview environment`);
      }
    }
    if (
      triggers?.workflow_dispatch?.inputs !== undefined ||
      JSON.stringify(document).includes("inputs.")
    ) {
      errors.push("Preview DAST target must not come from workflow input");
    }
  }
  return errors;
}

function actionlintBinary() {
  const configured = process.env.ACTIONLINT_BIN;
  const local = path.join(repoRoot, ".security-tools", "actionlint");
  for (const candidate of [configured, local].filter(Boolean)) {
    try {
      accessSync(candidate, constants.X_OK);
    } catch {
      // Use the YAML fallback when an optional local binary is unavailable.
      continue;
    }
    const version = spawnSync(candidate, ["-version"], { encoding: "utf8" });
    assert.equal(version.status, 0, `${candidate} version check failed`);
    assert.match(
      version.stdout,
      new RegExp(`^${tools.tools.actionlint.version.replaceAll(".", "\\.")}(?:$|\\s)`),
      `${candidate} does not match pinned actionlint ${tools.tools.actionlint.version}`,
    );
    return candidate;
  }
  const probe = spawnSync("actionlint", ["-version"], { encoding: "utf8" });
  return !probe.error &&
    probe.status === 0 &&
    new RegExp(`^${tools.tools.actionlint.version.replaceAll(".", "\\.")}(?:$|\\s)`).test(probe.stdout)
    ? "actionlint"
    : null;
}

function main() {
  const files = readdirSync(workflowDirectory)
    .filter((name) => /\.ya?ml$/.test(name))
    .sort();
  assert.ok(files.length > 0, "no GitHub workflows found");
  const errors = [];
  for (const name of files) {
    const filename = path.join(workflowDirectory, name);
    const document = YAML.parse(readFileSync(filename, "utf8"));
    errors.push(...validateWorkflowDocument(document, filename).map((error) => `${name}: ${error}`));
  }

  const binary = actionlintBinary();
  if (binary) {
    const result = spawnSync(binary, files.map((name) => path.join(workflowDirectory, name)), {
      cwd: repoRoot,
      encoding: "utf8",
    });
    if (result.status !== 0) errors.push(`actionlint:\n${result.stdout}${result.stderr}`);
  } else {
    console.log("actionlint is unavailable; using the deterministic YAML/semantic fallback validator.");
  }

  assert.deepEqual(errors, [], errors.join("\n"));
  console.log(`GitHub workflow gate passed (${files.length} workflows).`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`GitHub workflow gate failed: ${error.message}`);
    process.exitCode = 1;
  }
}
