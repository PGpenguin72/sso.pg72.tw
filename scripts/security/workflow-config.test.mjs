import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import YAML from "yaml";

import {
  dangerousCommandErrors,
  expectedPreviewJobCondition,
  loadWorkflowCommandContext,
  validateWorkflowCommands,
  validateWorkflowDocument,
  validateWorkflowEnvironment,
  workflowPolicy,
} from "./workflow-config.mjs";

const tools = {
  actions: {
    "actions/checkout": { version: "v1", sha: "a".repeat(40) },
  },
};

function workflow() {
  return {
    on: { push: { branches: ["main"] } },
    permissions: { contents: "read" },
    concurrency: { group: "test", "cancel-in-progress": true },
    jobs: {
      verify: {
        "runs-on": "ubuntu-24.04",
        "timeout-minutes": 10,
        steps: [
          {
            uses: `actions/checkout@${"a".repeat(40)}`,
            with: { "persist-credentials": false },
          },
        ],
      },
    },
  };
}

test("accepts least-privilege immutable workflows", () => {
  assert.deepEqual(validateWorkflowDocument(workflow(), "ci.yml", tools), []);
});

test("rejects tag-based actions and credential persistence", () => {
  const value = workflow();
  value.jobs.verify.steps[0] = { uses: "actions/checkout@v6" };
  const errors = validateWorkflowDocument(value, "ci.yml", tools);
  assert.ok(errors.some((error) => error.includes("immutable")));
  assert.ok(errors.some((error) => error.includes("persist-credentials")));
});

test("rejects remote or live Wrangler commands", () => {
  const value = workflow();
  value.jobs.verify.steps.push({ run: "pnpm wrangler deploy --remote" });
  const errors = validateWorkflowDocument(value, "ci.yml", tools);
  assert.ok(errors.some((error) => error.includes("remote/Preview Wrangler")));
  assert.ok(errors.some((error) => error.includes("non-dry-run")));
});

test("rejects local actions and reusable workflows instead of trusting hidden commands", () => {
  const local = workflow();
  local.jobs.verify.steps.push({ uses: "./.github/actions/unreviewed" });
  assert.ok(
    validateWorkflowDocument(local, "ci.yml", tools).some((error) =>
      error.includes("local actions are forbidden"),
    ),
  );

  const reusable = workflow();
  reusable.jobs.verify = {
    uses: "./.github/workflows/reusable.yml",
    "timeout-minutes": 10,
  };
  assert.ok(
    validateWorkflowDocument(reusable, "ci.yml", tools).some((error) =>
      error.includes("reusable workflows are forbidden"),
    ),
  );
});

test("accepts only the exact recursively reachable package-script graph", () => {
  const context = loadWorkflowCommandContext();
  for (const filename of ["ci.yml", "dast-preview.yml"]) {
    const document = YAML.parse(
      readFileSync(new URL(`../../.github/workflows/${filename}`, import.meta.url), "utf8"),
    );
    assert.deepEqual(validateWorkflowCommands(document, filename, context), []);
  }
});

test("enforces exact environment scopes and rejects inherited overrides", () => {
  const document = workflow();
  document.env = { CI: "1" };
  document.jobs.verify.env = { NO_COLOR: "1" };
  const policy = structuredClone(workflowPolicy);
  policy.environmentPolicy.scopes["ci.yml"].workflow = ["CI"];
  policy.environmentPolicy.scopes["ci.yml"].jobs.verify = ["NO_COLOR"];
  assert.deepEqual(validateWorkflowEnvironment(document, "ci.yml", policy), []);
  assert.deepEqual(validateWorkflowDocument(document, "ci.yml", tools, policy), []);

  document.jobs.verify.steps[0].env = { CI: "1" };
  policy.environmentPolicy.scopes["ci.yml"].steps["verify:0"] = ["CI"];
  assert.ok(
    validateWorkflowEnvironment(document, "ci.yml", policy).some((error) =>
      error.includes("overrides an inherited key"),
    ),
  );
});

test("rejects dynamic, secret-context, multiline, and default-denied env values", () => {
  for (const value of [
    "${{ secrets.CLOUDFLARE_API_TOKEN }}",
    "${{ github.token }}",
    "${{ vars.PGID_DAST_PREVIEW_ORIGIN }}-suffix",
    "1\nNODE_OPTIONS=--require ./payload.cjs",
  ]) {
    const document = workflow();
    document.env = { CI: value };
    const policy = structuredClone(workflowPolicy);
    policy.environmentPolicy.exactValues.CI = value;
    policy.environmentPolicy.allowedExpressionContexts.push(
      "secrets.CLOUDFLARE_API_TOKEN",
      "github.token",
    );
    policy.environmentPolicy.scopes["ci.yml"].workflow = ["CI"];
    assert.notDeepEqual(validateWorkflowEnvironment(document, "ci.yml", policy), [], value);
  }

  const unapproved = workflow();
  unapproved.jobs.verify.env = { SAFE_VALUE: "fixed" };
  assert.ok(
    validateWorkflowEnvironment(unapproved, "ci.yml").some((error) =>
      error.includes("keys differ from the exact scoped policy"),
    ),
  );
});

test("rejects execution preload, package-manager, PATH, and credential environment keys", () => {
  for (const key of [
    "NODE_OPTIONS",
    "BASH_ENV",
    "ENV",
    "PATH",
    "NODE_PATH",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "NPM_CONFIG_USERCONFIG",
    "npm_config_prefix",
    "PNPM_CONFIG_GLOBALCONFIG",
    "PNPM_HOME",
    "CLOUDFLARE_API_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
  ]) {
    const document = workflow();
    document.jobs.verify.env = { [key]: "fixed-value" };
    const policy = structuredClone(workflowPolicy);
    policy.environmentPolicy.exactValues[key] = "fixed-value";
    policy.environmentPolicy.scopes["ci.yml"].jobs.verify = [key];
    assert.ok(
      validateWorkflowEnvironment(document, "ci.yml", policy).some((error) =>
        error.includes("forbidden execution/credential key"),
      ),
      key,
    );
  }
});

test("document and command validators reject malicious env on an approved command", () => {
  const document = YAML.parse(
    readFileSync(new URL("../../.github/workflows/dast-preview.yml", import.meta.url), "utf8"),
  );
  const stepIndex = document.jobs["safe-dast"].steps.findIndex(
    (step) => step.run === "pnpm dast:preview",
  );
  document.jobs["safe-dast"].steps[stepIndex].env = {
    NODE_OPTIONS: "--require ./payload.cjs",
  };
  const policy = structuredClone(workflowPolicy);
  policy.environmentPolicy.exactValues.NODE_OPTIONS = "--require ./payload.cjs";
  policy.environmentPolicy.scopes["dast-preview.yml"].steps[`safe-dast:${stepIndex}`] = [
    "NODE_OPTIONS",
  ];
  const context = loadWorkflowCommandContext(undefined, policy);
  assert.notDeepEqual(validateWorkflowDocument(document, "dast-preview.yml", undefined, policy), []);
  assert.notDeepEqual(validateWorkflowCommands(document, "dast-preview.yml", context), []);
});

test("rejects multiline environment-file writes and command-level environment injection", () => {
  for (const command of [
    'echo "NODE_OPTIONS=--require ./payload.cjs" >> "$GITHUB_ENV"',
    'printf "%s\\n" "/tmp/payload" >> "${GITHUB_PATH}"',
    'cat <<EOF >> "$GITHUB_ENV"\nBASH_ENV=/tmp/payload\nEOF',
    "env NODE_OPTIONS=--import=./payload.mjs pnpm check",
    "npm_config_userconfig=/tmp/npmrc pnpm install --frozen-lockfile",
    "CLOUDFLARE_API_TOKEN=credential pnpm check",
    "echo '${{ secrets.CLOUDFLARE_API_TOKEN }}'",
  ]) {
    assert.notDeepEqual(dangerousCommandErrors(command), [], command);
  }
});

test("enforces exact Preview actor/ref condition and authorization step order", () => {
  const document = YAML.parse(
    readFileSync(new URL("../../.github/workflows/dast-preview.yml", import.meta.url), "utf8"),
  );
  assert.equal(document.jobs["safe-dast"].if, expectedPreviewJobCondition());
  assert.deepEqual(validateWorkflowDocument(document, "dast-preview.yml"), []);

  for (const mutate of [
    (value) => (value.jobs["safe-dast"].if = "${{ github.ref == 'refs/heads/main' }}"),
    (value) => value.jobs["safe-dast"].steps.splice(1, 1),
  ]) {
    const changed = structuredClone(document);
    mutate(changed);
    assert.ok(
      validateWorkflowDocument(changed, "dast-preview.yml").some((error) =>
        /actor and default-branch|authorization immediately after checkout/.test(error),
      ),
    );
  }
});

test("rejects indirect deploys even when package and leaf allowlists are changed together", () => {
  const document = YAML.parse(
    readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8"),
  );
  const context = structuredClone(loadWorkflowCommandContext());
  context.packagesByRoot["."].scripts["security:check"] = "wrangler deploy";
  context.policy.approvedPackageScripts["."]["security:check"] = "wrangler deploy";
  context.policy.allowedLeafCommands.push("wrangler deploy");
  const errors = validateWorkflowCommands(document, "ci.yml", context);
  assert.ok(errors.some((error) => error.includes("non-dry-run deployment")));
});

test("rejects unallowlisted local scripts and nonlocal network commands", () => {
  const document = YAML.parse(
    readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8"),
  );
  const context = structuredClone(loadWorkflowCommandContext());
  context.packagesByRoot["."].scripts["security:check"] = "node scripts/unreviewed.mjs";
  context.policy.approvedPackageScripts["."]["security:check"] = "node scripts/unreviewed.mjs";
  context.policy.allowedLeafCommands.push("node scripts/unreviewed.mjs");
  const errors = validateWorkflowCommands(document, "ci.yml", context);
  assert.ok(errors.some((error) => error.includes("unapproved local script")));

  for (const command of [
    "curl https://example.invalid",
    "wget https://example.invalid/payload",
    "wrangler d1 execute pg72-id --remote",
    "wrangler kv key put --namespace-id x key value",
    "wrangler r2 object put bucket/key --file payload",
    "wrangler queues create events",
    "wrangler pages deploy dist",
    "wrangler secret put TOKEN",
    "wrangler deploy --preview",
  ]) {
    assert.notDeepEqual(dangerousCommandErrors(command), [], `${command} was accepted`);
  }
});

test("requires protected manual Preview DAST without target input", () => {
  const value = workflow();
  value.on = { workflow_dispatch: { inputs: { target: { required: true } } } };
  const errors = validateWorkflowDocument(value, "dast-preview.yml", tools);
  assert.ok(errors.some((error) => error.includes("protected isolated-preview")));
  assert.ok(errors.some((error) => error.includes("workflow input")));
});
