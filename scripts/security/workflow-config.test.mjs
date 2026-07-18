import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import YAML from "yaml";

import {
  completePackageScriptDigest,
  dangerousCommandErrors,
  expectedPreviewJobCondition,
  loadWorkflowCommandContext,
  reachablePackageScriptDigest,
  validateArtifactUploads,
  validateCompletePackageScriptIdentity,
  validateEarlyIdentityStep,
  validateReachablePackageScriptIdentity,
  validateWorkflowCommands,
  validateWorkflowDocument,
  validateWorkflowEnvironment,
  validateWorkflowFileSet,
  validateWorkflowSourceIdentity,
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
          {
            name: "Verify release identities before setup",
            run: "node scripts/security/release-identity.mjs",
          },
        ],
      },
    },
  };
}

function replaceExactly(source, search, replacement) {
  assert.equal(source.split(search).length, 2, `mutation anchor must occur exactly once: ${search}`);
  return source.replace(search, replacement);
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
  assert.ok(errors.some((error) => error.includes("code-owned exact command")));
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

  const document = YAML.parse(
    readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8"),
  );
  assert.deepEqual(Object.keys(document.on).sort(), ["pull_request", "push"]);
  assert.equal(
    document.jobs.verify.steps.some((step) => step.run === "pnpm dast:local"),
    false,
  );

  assert.equal(
    context.packagesByRoot["."].scripts["dast:local"],
    "node scripts/security/dast-local.mjs",
  );

  const changed = structuredClone(document);
  const uploadIndex = changed.jobs.verify.steps.findIndex((step) =>
    step.uses?.startsWith("actions/upload-artifact@"),
  );
  changed.jobs.verify.steps.splice(uploadIndex, 0, {
    name: "Run localhost-only DAST",
    run: "pnpm dast:local",
  });
  assert.ok(
    validateWorkflowCommands(changed, "ci.yml", context).some((error) =>
      error.includes("job/step run map differs"),
    ),
  );
});

test("pins the exact workflow file set and raw LF-only tracked bytes", () => {
  assert.deepEqual(validateWorkflowFileSet(["dast-preview.yml", "ci.yml"]), []);
  assert.notDeepEqual(validateWorkflowFileSet(["ci.yml"]), []);
  assert.notDeepEqual(validateWorkflowFileSet(["ci.yml", "dast-preview.yml", "extra.yml"]), []);

  for (const filename of ["ci.yml", "dast-preview.yml"]) {
    const source = readFileSync(
      new URL(`../../.github/workflows/${filename}`, import.meta.url),
    );
    assert.deepEqual(validateWorkflowSourceIdentity(source, filename), []);
    const crlf = Buffer.from(source.toString("utf8").replaceAll("\n", "\r\n"));
    assert.notDeepEqual(validateWorkflowSourceIdentity(crlf, filename), [], filename);
  }
});

test("rejects the complete workflow reviewer mutation matrix at the raw identity layer", () => {
  const source = readFileSync(
    new URL("../../.github/workflows/ci.yml", import.meta.url),
    "utf8",
  );
  const checkoutWith = "        with:\n          persist-credentials: false\n          fetch-depth: 0";
  const gateStep = "      - name: Run repository gate\n        run: pnpm check";
  const jobBoundary = "    timeout-minutes: 30\n\n    steps:";
  const mutations = [
    ["action uses", (value) => replaceExactly(value, "actions/checkout@df4cb1c", "actions/checkout@ef4cb1c")],
    ["checkout repository", (value) => replaceExactly(value, checkoutWith, `${checkoutWith}\n          repository: attacker/repository`)],
    ["checkout ref", (value) => replaceExactly(value, checkoutWith, `${checkoutWith}\n          ref: attacker-ref`)],
    ["checkout token", (value) => replaceExactly(value, checkoutWith, `${checkoutWith}\n          token: \${{ github.token }}`)],
    ["checkout path", (value) => replaceExactly(value, checkoutWith, `${checkoutWith}\n          path: nested`)],
    ["setup extra with", (value) => replaceExactly(value, "          version: 11.5.0", "          version: 11.5.0\n          standalone: true")],
    ["job if", (value) => replaceExactly(value, "  verify:\n    runs-on:", "  verify:\n    if: \${{ false }}\n    runs-on:")],
    ["step if", (value) => replaceExactly(value, gateStep, `${gateStep}\n        if: \${{ false }}`)],
    ["continue-on-error", (value) => replaceExactly(value, gateStep, `${gateStep}\n        continue-on-error: true`)],
    ["timeout", (value) => replaceExactly(value, "    timeout-minutes: 30", "    timeout-minutes: 31")],
    ["needs", (value) => replaceExactly(value, "  verify:\n    runs-on:", "  verify:\n    needs: bootstrap\n    runs-on:")],
    ["environment", (value) => replaceExactly(value, "    runs-on: ubuntu-24.04", "    runs-on: ubuntu-24.04\n    environment: production")],
    ["job permissions", (value) => replaceExactly(value, "    timeout-minutes: 30", "    timeout-minutes: 30\n    permissions:\n      contents: write")],
    ["top-level permissions", (value) => replaceExactly(value, "  contents: read", "  contents: write")],
    ["runs-on", (value) => replaceExactly(value, "    runs-on: ubuntu-24.04", "    runs-on: self-hosted")],
    ["strategy", (value) => replaceExactly(value, jobBoundary, "    timeout-minutes: 30\n    strategy:\n      matrix:\n        node: [24]\n\n    steps:")],
    ["container", (value) => replaceExactly(value, jobBoundary, "    timeout-minutes: 30\n    container: node:24\n\n    steps:")],
    ["services", (value) => replaceExactly(value, jobBoundary, "    timeout-minutes: 30\n    services:\n      cache:\n        image: redis:7\n\n    steps:")],
    ["workflow env", (value) => replaceExactly(value, "permissions:\n  contents: read", "env:\n  NODE_OPTIONS: --require ./payload.cjs\n\npermissions:\n  contents: read")],
    ["job env", (value) => replaceExactly(value, "    timeout-minutes: 30", "    timeout-minutes: 30\n    env:\n      NODE_OPTIONS: --require ./payload.cjs")],
    ["step env", (value) => replaceExactly(value, gateStep, `${gateStep}\n        env:\n          NODE_OPTIONS: --require ./payload.cjs`)],
    ["run", (value) => replaceExactly(value, "        run: pnpm check", "        run: pnpm check && echo bypass")],
    ["shell", (value) => replaceExactly(value, gateStep, `${gateStep}\n        shell: sh`)],
    ["working-directory", (value) => replaceExactly(value, gateStep, `${gateStep}\n        working-directory: /tmp`)],
    ["whole-checkout upload", (value) => replaceExactly(value, "          path: .artifacts/release", "          path: .")],
    ["upload retention", (value) => replaceExactly(value, "          retention-days: 7", "          retention-days: 30")],
    ["upload hidden files", (value) => replaceExactly(value, "          include-hidden-files: false", "          include-hidden-files: true")],
  ];

  for (const [label, mutate] of mutations) {
    const changed = mutate(source);
    assert.notEqual(changed, source, label);
    assert.notDeepEqual(
      validateWorkflowSourceIdentity(Buffer.from(changed), "ci.yml"),
      [],
      label,
    );
  }
});

test("pins reachable package-script names and complete values to one code-owned digest", () => {
  const baseline = loadWorkflowCommandContext();
  assert.equal(
    reachablePackageScriptDigest(baseline),
    "6027cfa69c065976cec03896dccfcaaaeb821288ed294f45f325a403d4832c42",
  );
  assert.deepEqual(validateReachablePackageScriptIdentity(baseline), []);

  for (const mutate of [
    (context) => (context.packagesByRoot["."].scripts.check += " && echo bypass"),
    (context) => delete context.packagesByRoot["apps/sso"].scripts.build,
    (context) => {
      context.packagesByRoot.wiki.scripts.verify = context.packagesByRoot.wiki.scripts.check;
      delete context.packagesByRoot.wiki.scripts.check;
    },
  ]) {
    const context = structuredClone(baseline);
    mutate(context);
    assert.notDeepEqual(validateReachablePackageScriptIdentity(context), []);
  }
});

test("pins every workspace scripts object including otherwise unreachable names", () => {
  const baseline = loadWorkflowCommandContext();
  assert.equal(
    completePackageScriptDigest(baseline),
    "9785193a907eec3edd5152a6597353e9f80beea18775c060a8106aa7e97fdb32",
  );
  assert.deepEqual(validateCompletePackageScriptIdentity(baseline), []);

  for (const mutate of [
    (context) => (context.packagesByRoot["."].scripts.unreviewed = "node scripts/unreviewed.mjs"),
    (context) => delete context.packagesByRoot["apps/sso"].scripts.dev,
    (context) => (context.packagesByRoot["apps/test-rp"].scripts["db:migrate:local"] += " --remote"),
    (context) => (context.packagesByRoot.wiki.scripts.preview = "vitepress preview ./other"),
  ]) {
    const context = structuredClone(baseline);
    mutate(context);
    assert.notDeepEqual(validateCompletePackageScriptIdentity(context), []);
  }
});

test("models implicit pre/post hooks for root and filtered pnpm scripts", () => {
  const ci = YAML.parse(
    readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8"),
  );
  for (const [packageRoot, hook] of [
    [".", "precheck"],
    [".", "postcheck"],
    ["apps/sso", "precheck"],
    ["apps/sso", "postcheck"],
  ]) {
    const context = structuredClone(loadWorkflowCommandContext());
    context.packagesByRoot[packageRoot].scripts[hook] = "node scripts/unreviewed.mjs";
    const errors = validateWorkflowCommands(ci, "ci.yml", context);
    assert.ok(
      errors.some((error) => error.includes(`package script ${packageRoot}:${hook}`)),
      `${packageRoot}:${hook}`,
    );
  }
});

test("models every install lifecycle in root and filtered workspaces", () => {
  const ci = YAML.parse(
    readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8"),
  );
  for (const packageRoot of [".", "apps/test-rp"]) {
    for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
      const context = structuredClone(loadWorkflowCommandContext());
      context.packagesByRoot[packageRoot].scripts[hook] = "node scripts/unreviewed.mjs";
      const errors = validateWorkflowCommands(ci, "ci.yml", context);
      assert.ok(
        errors.some((error) => error.includes(`package script ${packageRoot}:${hook}`)),
        `${packageRoot}:${hook}`,
      );
    }
  }
});

test("requires early identity immediately after checkout in every workflow", () => {
  for (const filename of ["ci.yml", "dast-preview.yml"]) {
    const baseline = YAML.parse(
      readFileSync(new URL(`../../.github/workflows/${filename}`, import.meta.url), "utf8"),
    );
    assert.deepEqual(validateEarlyIdentityStep(baseline, filename), []);
    const job = Object.values(baseline.jobs)[0];

    const removed = structuredClone(baseline);
    Object.values(removed.jobs)[0].steps.splice(1, 1);
    assert.notDeepEqual(validateEarlyIdentityStep(removed, filename), []);

    const reordered = structuredClone(baseline);
    const reorderedSteps = Object.values(reordered.jobs)[0].steps;
    [reorderedSteps[1], reorderedSteps[2]] = [reorderedSteps[2], reorderedSteps[1]];
    assert.notDeepEqual(validateEarlyIdentityStep(reordered, filename), []);

    assert.equal(job.steps[1].run, "node scripts/security/release-identity.mjs");
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

test("rejects execution, credential, and every Cloudflare/Wrangler environment key", () => {
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
    "CLOUDFLARE_EMAIL",
    "CLOUDFLARE_ACCESS_CLIENT_ID",
    "CLOUDFLARE_ACCESS_CLIENT_SECRET",
    "CLOUDFLARE_ENV",
    "CLOUDFLARE_API_BASE_URL",
    "CLOUDFLARE_ACCOUNT_ID",
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_API_KEY",
    "CF_EMAIL",
    "CF_ACCESS_CLIENT_ID",
    "CF_ACCESS_CLIENT_SECRET",
    "CF_ENV",
    "CF_API_BASE_URL",
    "CF_ACCOUNT_ID",
    "cf_api_token",
    "CF_API_KEY",
    "WRANGLER_EMAIL",
    "WRANGLER_ACCESS_CLIENT_ID",
    "WRANGLER_ACCESS_CLIENT_SECRET",
    "WRANGLER_ENV",
    "WRANGLER_ENVIRONMENT",
    "WRANGLER_API_BASE_URL",
    "WRANGLER_ACCOUNT_ID",
    "WRANGLER_API_TOKEN",
    "WRANGLER_API_KEY",
    "WRANGLER_SEND_METRICS",
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

test("code-owned policy rejects forbidden and newly invented environment allowances", () => {
  for (const [group, key] of [
    ["exactValues", "CLOUDFLARE_EMAIL"],
    ["safeStaticValues", "CF_ACCOUNT_ID"],
    ["safeStaticValues", "WRANGLER_SEND_METRICS"],
    ["safeStaticValues", "REVIEWED_BUT_NOT_CODE_OWNED"],
  ]) {
    const policy = structuredClone(workflowPolicy);
    policy.environmentPolicy[group][key] = "fixed-value";
    const errors = validateWorkflowEnvironment(workflow(), "ci.yml", policy);
    assert.ok(
      errors.some((error) => /code-owned forbidden|outside the code-owned allowlist/.test(error)),
      key,
    );
  }

  const document = YAML.parse(
    readFileSync(new URL("../../.github/workflows/dast-preview.yml", import.meta.url), "utf8"),
  );
  document.jobs["safe-dast"].env.DAST_TARGET = "${{ vars.UNREVIEWED_TARGET }}";
  const policy = structuredClone(workflowPolicy);
  policy.environmentPolicy.exactValues.DAST_TARGET = "${{ vars.UNREVIEWED_TARGET }}";
  policy.environmentPolicy.allowedExpressionContexts = [
    ...policy.environmentPolicy.allowedExpressionContexts,
    "vars.UNREVIEWED_TARGET",
  ];
  const errors = validateWorkflowEnvironment(document, "dast-preview.yml", policy);
  assert.ok(errors.some((error) => error.includes("code-owned value")));
  assert.ok(errors.some((error) => error.includes("code-owned allowlist")));
});

test("hard-denies a forbidden inherited workflow environment even with matching policy", () => {
  const document = workflow();
  document.env = { CLOUDFLARE_EMAIL: "operator@example.invalid" };
  const policy = structuredClone(workflowPolicy);
  policy.environmentPolicy.exactValues.CLOUDFLARE_EMAIL = "operator@example.invalid";
  policy.environmentPolicy.scopes["ci.yml"].workflow = ["CLOUDFLARE_EMAIL"];
  assert.ok(
    validateWorkflowEnvironment(document, "ci.yml", policy).some((error) =>
      error.includes("forbidden execution/credential key"),
    ),
  );
});

test("document and command validators reject malicious env on an approved command", () => {
  for (const [key, value] of [
    ["NODE_OPTIONS", "--require ./payload.cjs"],
    ["CLOUDFLARE_EMAIL", "operator@example.invalid"],
    ["CF_ACCOUNT_ID", "preview-account"],
    ["WRANGLER_API_BASE_URL", "https://example.invalid"],
  ]) {
    const document = YAML.parse(
      readFileSync(new URL("../../.github/workflows/dast-preview.yml", import.meta.url), "utf8"),
    );
    const stepIndex = document.jobs["safe-dast"].steps.findIndex(
      (step) => step.run === "pnpm dast:preview",
    );
    document.jobs["safe-dast"].steps[stepIndex].env = { [key]: value };
    const policy = structuredClone(workflowPolicy);
    policy.environmentPolicy.exactValues[key] = value;
    policy.environmentPolicy.scopes["dast-preview.yml"].steps[`safe-dast:${stepIndex}`] = [key];
    const context = loadWorkflowCommandContext(undefined, policy);
    assert.notDeepEqual(
      validateWorkflowDocument(document, "dast-preview.yml", undefined, policy),
      [],
      key,
    );
    assert.notDeepEqual(validateWorkflowCommands(document, "dast-preview.yml", context), [], key);
  }
});

test("rejects multiline environment-file writes and command-level environment injection", () => {
  for (const command of [
    'echo "NODE_OPTIONS=--require ./payload.cjs" >> "$GITHUB_ENV"',
    'printf "%s\\n" "/tmp/payload" >> "${GITHUB_PATH}"',
    'cat <<EOF >> "$GITHUB_ENV"\nBASH_ENV=/tmp/payload\nEOF',
    "env NODE_OPTIONS=--import=./payload.mjs pnpm check",
    "npm_config_userconfig=/tmp/npmrc pnpm install --frozen-lockfile",
    "CLOUDFLARE_EMAIL=operator@example.invalid pnpm check",
    "CLOUDFLARE_API_TOKEN=credential pnpm check",
    "env CF_ACCOUNT_ID=preview-account pnpm check",
    "export WRANGLER_ENV=preview; pnpm check",
    'echo "CF_API_TOKEN=credential" >> "$GITHUB_ENV"',
    "echo '${{ secrets.CLOUDFLARE_API_TOKEN }}'",
  ]) {
    assert.notDeepEqual(dangerousCommandErrors(command), [], command);
  }
});

test("exact job and step maps reject shell quote composition, redirects, and control bytes", () => {
  const baseline = YAML.parse(
    readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8"),
  );
  const context = loadWorkflowCommandContext();
  const stepIndex = baseline.jobs.verify.steps.findIndex((step) => step.run === "pnpm check");
  for (const command of [
    '"pnpm" "check"',
    "p'n'p'm' check",
    "pnpm check && curl https://example.invalid",
    "PATH=/tmp:$PATH pnpm check",
    'echo "NODE_OPTIONS=--require ./payload.cjs" >> "$GITHUB_ENV"',
    "pnpm check > gate.txt",
    "pnpm check\r\n",
    "pnpm check\u0000",
  ]) {
    const document = structuredClone(baseline);
    document.jobs.verify.steps[stepIndex].run = command;
    assert.notDeepEqual(validateWorkflowCommands(document, "ci.yml", context), [], command);
    assert.notDeepEqual(dangerousCommandErrors(command), [], command);
  }
});

test("fixes the release artifact upload to one reviewed directory and exact options", () => {
  const baseline = YAML.parse(
    readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8"),
  );
  assert.deepEqual(validateArtifactUploads(baseline, "ci.yml"), []);
  const uploadIndex = baseline.jobs.verify.steps.findIndex((step) =>
    step.uses?.startsWith("actions/upload-artifact@"),
  );

  for (const mutate of [
    (step) => (step.with.path = "."),
    (step) => (step.with.path = "**/*"),
    (step) => (step.with.path = ".artifacts/release/"),
    (step) => (step.with.name = "release-assurance"),
    (step) => (step.with["if-no-files-found"] = "warn"),
    (step) => (step.with["retention-days"] = 30),
    (step) => (step.with["include-hidden-files"] = true),
    (step) => delete step.with["include-hidden-files"],
    (step) => (step.if = "always()"),
  ]) {
    const document = structuredClone(baseline);
    mutate(document.jobs.verify.steps[uploadIndex]);
    assert.notDeepEqual(validateArtifactUploads(document, "ci.yml"), []);
  }

  const duplicate = structuredClone(baseline);
  duplicate.jobs.verify.steps.push(structuredClone(duplicate.jobs.verify.steps[uploadIndex]));
  assert.notDeepEqual(validateArtifactUploads(duplicate, "ci.yml"), []);
});

test("enforces exact Preview actor/ref condition and authorization step order", () => {
  const document = YAML.parse(
    readFileSync(new URL("../../.github/workflows/dast-preview.yml", import.meta.url), "utf8"),
  );
  assert.equal(document.jobs["safe-dast"].if, expectedPreviewJobCondition());
  assert.deepEqual(validateWorkflowDocument(document, "dast-preview.yml"), []);
  const previewEnvironmentKeys = Object.keys(document.jobs["safe-dast"].env).sort();
  assert.deepEqual(previewEnvironmentKeys, [
    "DAST_ALLOWED_PREVIEW_ORIGIN",
    "DAST_PREVIEW_OPT_IN",
    "DAST_TARGET",
  ]);
  assert.ok(
    previewEnvironmentKeys.every(
      (key) => !/^(?:CLOUDFLARE_|CF_|WRANGLER_)/i.test(key),
    ),
  );

  for (const mutate of [
    (value) => (value.jobs["safe-dast"].if = "${{ github.ref == 'refs/heads/main' }}"),
    (value) => value.jobs["safe-dast"].steps.splice(1, 1),
  ]) {
    const changed = structuredClone(document);
    mutate(changed);
    assert.ok(
      validateWorkflowDocument(changed, "dast-preview.yml").some((error) =>
        /actor and default-branch|early identity|identity check immediately/.test(error),
      ),
    );
  }
});

test("rejects indirect deploys even when policy command extensions are changed together", () => {
  const document = YAML.parse(
    readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8"),
  );
  const context = structuredClone(loadWorkflowCommandContext());
  context.packagesByRoot["."].scripts["security:check"] = "wrangler deploy";
  context.policy.approvedPackageScripts = { ".": { "security:check": "wrangler deploy" } };
  context.policy.allowedLeafCommands = ["wrangler deploy"];
  const errors = validateWorkflowCommands(document, "ci.yml", context);
  assert.ok(errors.some((error) => error.includes("must not define commands")));
  assert.ok(errors.some((error) => error.includes("code-owned exact value")));
});

test("rejects unallowlisted local scripts and nonlocal network commands", () => {
  const document = YAML.parse(
    readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8"),
  );
  const context = structuredClone(loadWorkflowCommandContext());
  context.packagesByRoot["."].scripts["security:check"] = "node scripts/unreviewed.mjs";
  const errors = validateWorkflowCommands(document, "ci.yml", context);
  assert.ok(errors.some((error) => error.includes("code-owned exact value")));

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
