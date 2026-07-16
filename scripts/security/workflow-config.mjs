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
export const workflowPolicy = JSON.parse(
  readFileSync(new URL("../../security/workflow-policy.json", import.meta.url), "utf8"),
);
export const dastPolicy = JSON.parse(
  readFileSync(new URL("../../security/dast-policy.json", import.meta.url), "utf8"),
);

function entries(value) {
  return value && typeof value === "object" ? Object.entries(value) : [];
}

function actorCondition(field, actors) {
  const clauses = actors.map((actor) => `${field} == '${actor}'`);
  return clauses.length === 1 ? clauses[0] : `(${clauses.join(" || ")})`;
}

export function expectedPreviewJobCondition(policy = dastPolicy) {
  return `\${{ ${actorCondition("github.actor", policy.preview.approvedActors)} && ${actorCondition(
    "github.triggering_actor",
    policy.preview.approvedActors,
  )} && github.ref == '${policy.preview.defaultRef}' }}`;
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
    if (job.uses !== undefined) errors.push(`${jobName} reusable workflows are forbidden`);
    if (!Number.isInteger(job["timeout-minutes"]) || job["timeout-minutes"] <= 0) {
      errors.push(`${jobName} must have a positive timeout-minutes`);
    }
    if (job.permissions !== undefined) errors.push(`${jobName} must not elevate permissions`);
    if (!Array.isArray(job.steps)) errors.push(`${jobName} steps must be an array`);

    for (const [index, step] of (job.steps ?? []).entries()) {
      const label = `${jobName}.steps[${index}]`;
      if (typeof step.uses === "string" && step.uses.startsWith("./")) {
        errors.push(`${label} local actions are forbidden`);
      } else if (typeof step.uses === "string") {
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
        errors.push(...dangerousCommandErrors(step.run).map((error) => `${label} ${error}`));
        if (step["working-directory"] !== undefined) errors.push(`${label} working-directory is forbidden`);
        if (step.shell !== undefined && step.shell !== "bash") errors.push(`${label} shell must be bash`);
      }
    }
  }

  if (path.basename(filename) === "dast-preview.yml") {
    if (Object.keys(triggers ?? {}).join(",") !== "workflow_dispatch") {
      errors.push("Preview DAST must be workflow_dispatch only");
    }
    for (const [jobName, job] of entries(document.jobs)) {
      if (job.environment !== dastPolicy.preview.environment) {
        errors.push(`${jobName} must use the protected isolated-preview environment`);
      }
      if (job.if !== expectedPreviewJobCondition()) {
        errors.push(`${jobName} must enforce exact approved actor and default-branch policy at job level`);
      }
      if (
        job.steps?.[0]?.uses?.split("@")[0] !== "actions/checkout" ||
        job.steps?.[1]?.run !== "node scripts/security/dast.mjs --authorize-only --preview"
      ) {
        errors.push(`${jobName} must run the repository Preview authorization immediately after checkout`);
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

function exactPattern(value) {
  return new RegExp(
    `^${value.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", "[^/]*")}$`,
  );
}

export function dangerousCommandErrors(command) {
  const errors = [];
  if (/(?:^|[\s;&|])(?:curl|wget|nc|ncat|ssh|scp|rsync)\b/i.test(command)) {
    errors.push("contains a forbidden nonlocal network command");
  }
  if (/https?:\/\/(?!127\.0\.0\.1(?::\d+)?(?:[/'"\s]|$))/i.test(command)) {
    errors.push("contains a forbidden nonlocal network target");
  }
  if (/\bwrangler\b[^\n]*(?:--remote|--preview)\b/i.test(command)) {
    errors.push("contains a remote/Preview Wrangler command");
  }
  if (/\bwrangler\s+(?:d1|kv|r2|queues?|pages|secret|secrets-store)\b/i.test(command)) {
    errors.push("contains a forbidden Wrangler resource command");
  }
  if (/\bwrangler\s+(?:deploy|versions\s+upload)\b/i.test(command) && !/--dry-run\b/.test(command)) {
    errors.push("contains a non-dry-run deployment command");
  }
  return errors;
}

export function loadWorkflowCommandContext(root = repoRoot, policy = workflowPolicy) {
  const packagesByRoot = {};
  const packageNameToRoot = {};
  for (const packageRoot of policy.packageRoots) {
    const manifest = JSON.parse(
      readFileSync(path.join(root, packageRoot, "package.json"), "utf8"),
    );
    packagesByRoot[packageRoot] = { name: manifest.name, scripts: manifest.scripts ?? {} };
    packageNameToRoot[manifest.name] = packageRoot;
  }
  return { policy, packagesByRoot, packageNameToRoot };
}

function localScriptError(command, packageRoot, policy) {
  if (!command.startsWith("node ")) return null;
  const tokens = command.split(/\s+/);
  const scriptIndex = tokens[1] === "--test" ? 2 : 1;
  const script = tokens[scriptIndex];
  if (!script || script.startsWith("-")) return `does not name an approved local Node script: ${command}`;
  const resolved = path.posix.normalize(path.posix.join(packageRoot, script));
  const allowed = policy.allowedLocalScripts.some((entry) => exactPattern(entry).test(resolved));
  return allowed ? null : `uses an unapproved local script: ${resolved}`;
}

function expandPackageScript(packageRoot, scriptName, context, state) {
  const key = `${packageRoot}:${scriptName}`;
  if (state.stack.includes(key)) {
    state.errors.push(`package script cycle: ${[...state.stack, key].join(" -> ")}`);
    return;
  }
  const packageData = context.packagesByRoot[packageRoot];
  const actual = packageData?.scripts?.[scriptName];
  const approved = context.policy.approvedPackageScripts[packageRoot]?.[scriptName];
  if (typeof actual !== "string") {
    state.errors.push(`missing package script ${key}`);
    return;
  }
  if (approved !== actual) {
    state.errors.push(`package script ${key} is not the exact approved command`);
    return;
  }
  state.stack.push(key);
  for (const command of actual.split("&&").map((value) => value.trim())) {
    expandCommand(command, packageRoot, context, state);
  }
  state.stack.pop();
}

function expandCommand(command, packageRoot, context, state) {
  state.errors.push(...dangerousCommandErrors(command));
  if (context.policy.allowedLeafCommands.includes(command)) {
    const localError = localScriptError(command, packageRoot, context.policy);
    if (localError) state.errors.push(localError);
    else state.leaves.push(`${packageRoot}:${command}`);
    return;
  }
  const tokens = command.split(/\s+/);
  if (tokens[0] !== "pnpm") {
    state.errors.push(`unapproved leaf command: ${command}`);
    return;
  }
  if (tokens[1] === "--filter" && tokens.length === 4) {
    const targetRoot = context.packageNameToRoot[tokens[2]];
    if (!targetRoot) state.errors.push(`unknown filtered package ${tokens[2]}`);
    else expandPackageScript(targetRoot, tokens[3], context, state);
    return;
  }
  const scriptName = tokens[1] === "run" && tokens.length === 3 ? tokens[2] : tokens.length === 2 ? tokens[1] : null;
  if (!scriptName) {
    state.errors.push(`unsupported pnpm command: ${command}`);
    return;
  }
  expandPackageScript(packageRoot, scriptName, context, state);
}

export function validateWorkflowCommands(document, filename, context) {
  const errors = [];
  const allowed = context.policy.workflows[path.basename(filename)]?.allowedRunCommands;
  if (!allowed) return [`${path.basename(filename)} lacks an explicit command policy`];
  const actualRunCommands = entries(document.jobs).flatMap(([, job]) =>
    (job.steps ?? []).flatMap((step) => (typeof step.run === "string" ? [step.run] : [])),
  );
  if (JSON.stringify(actualRunCommands) !== JSON.stringify(allowed)) {
    errors.push(`${path.basename(filename)} run commands/order differ from the exact policy`);
  }
  for (const [jobName, job] of entries(document.jobs)) {
    for (const [index, step] of (job.steps ?? []).entries()) {
      if (typeof step.run !== "string") continue;
      const label = `${jobName}.steps[${index}]`;
      if (!allowed.includes(step.run)) {
        errors.push(`${label} run command is not explicitly approved`);
        continue;
      }
      const state = { errors: [], leaves: [], stack: [] };
      expandCommand(step.run, ".", context, state);
      errors.push(...state.errors.map((error) => `${label} ${error}`));
    }
  }
  return [...new Set(errors)];
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
  if (workflowPolicy.schemaVersion !== 1) errors.push("workflow policy schemaVersion must be 1");
  if (dastPolicy.schemaVersion !== 2) errors.push("DAST policy schemaVersion must be 2");
  if (JSON.stringify(dastPolicy.preview.approvedActors) !== JSON.stringify(["PGpenguin72"])) {
    errors.push("DAST policy approved actors must be exactly PGpenguin72");
  }
  if (dastPolicy.preview.defaultRef !== "refs/heads/main") {
    errors.push("DAST policy default ref must be refs/heads/main");
  }
  const commandContext = loadWorkflowCommandContext();
  for (const name of files) {
    const filename = path.join(workflowDirectory, name);
    const document = YAML.parse(readFileSync(filename, "utf8"));
    errors.push(...validateWorkflowDocument(document, filename).map((error) => `${name}: ${error}`));
    errors.push(...validateWorkflowCommands(document, filename, commandContext).map((error) => `${name}: ${error}`));
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
