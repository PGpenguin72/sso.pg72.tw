import assert from "node:assert/strict";
import test from "node:test";

import { validateWorkflowDocument } from "./workflow-config.mjs";

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
  assert.ok(errors.some((error) => error.includes("remote Wrangler")));
  assert.ok(errors.some((error) => error.includes("non-dry-run")));
});

test("requires protected manual Preview DAST without target input", () => {
  const value = workflow();
  value.on = { workflow_dispatch: { inputs: { target: { required: true } } } };
  const errors = validateWorkflowDocument(value, "dast-preview.yml", tools);
  assert.ok(errors.some((error) => error.includes("protected isolated-preview")));
  assert.ok(errors.some((error) => error.includes("workflow input")));
});
