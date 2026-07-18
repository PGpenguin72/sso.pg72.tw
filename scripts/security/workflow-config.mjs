import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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

const codeOwnedExactEnvironmentValues = Object.freeze({
  DAST_ALLOWED_PREVIEW_ORIGIN: "${{ vars.PGID_DAST_PREVIEW_ORIGIN }}",
  DAST_PREVIEW_OPT_IN: "${{ vars.PGID_DAST_PREVIEW_OPT_IN }}",
  DAST_TARGET: "${{ vars.PGID_DAST_PREVIEW_ORIGIN }}",
});
const codeOwnedStaticEnvironmentValues = Object.freeze({
  CI: "1",
  NO_COLOR: "1",
});
const codeOwnedEnvironmentValues = Object.freeze({
  ...codeOwnedExactEnvironmentValues,
  ...codeOwnedStaticEnvironmentValues,
});
const codeOwnedExpressionContexts = Object.freeze([
  "vars.PGID_DAST_PREVIEW_ORIGIN",
  "vars.PGID_DAST_PREVIEW_OPT_IN",
]);
const codeOwnedPackageRoots = Object.freeze([".", "apps/sso", "apps/test-rp", "wiki"]);
const codeOwnedWorkflowSourceDigests = Object.freeze({
  "ci.yml": "e907641bdb2659f86a922ad696c49d8d3ab117a8ffff117891ac281c6a50bfda",
  "dast-preview.yml": "9826177b4315c8f0ca29fe812508349d1ac0fcab6e3cce9d1e0772c9c124e711",
});
const codeOwnedReachablePackageScriptDigest =
  "6027cfa69c065976cec03896dccfcaaaeb821288ed294f45f325a403d4832c42";
const codeOwnedCompletePackageScriptDigest =
  "9785193a907eec3edd5152a6597353e9f80beea18775c060a8106aa7e97fdb32";
const codeOwnedWorkflowRuns = Object.freeze({
  "ci.yml": Object.freeze({
    "verify:1": "node scripts/security/release-identity.mjs",
    "verify:4": "pnpm install --frozen-lockfile",
    "verify:5": "pnpm check",
    "verify:6": "pnpm security:tools:install",
    "verify:7": "pnpm security:check",
  }),
  "dast-preview.yml": Object.freeze({
    "safe-dast:1": "node scripts/security/release-identity.mjs",
    "safe-dast:2": "node scripts/security/dast.mjs --authorize-only --preview",
    "safe-dast:5": "pnpm install --frozen-lockfile",
    "safe-dast:6": "pnpm dast:preview",
  }),
});
const codeOwnedReachablePackageScripts = Object.freeze({
  ".": Object.freeze({
    check: "pnpm test:clean-dist && pnpm test:public-readiness && pnpm --filter @pg72/id check && pnpm --filter @pg72/test-rp check && pnpm --filter @pg72/wiki check",
    "dast:preview": "node scripts/security/dast.mjs --preview",
    "security:artifact": "node scripts/security/artifact-gate.mjs",
    "security:audit": "node scripts/security/accepted-advisories.mjs",
    "security:check": "pnpm test:security && pnpm security:static && pnpm security:secrets && pnpm security:config && pnpm security:audit && pnpm security:artifact && pnpm security:inventory",
    "security:config": "node scripts/security/workflow-config.mjs && node scripts/security/wrangler-config.mjs",
    "security:inventory": "node scripts/security/dependency-inventory.mjs",
    "security:secrets": "node scripts/security/secret-scan.mjs",
    "security:static": "oxlint --type-aware apps/sso/worker apps/test-rp/worker",
    "security:tools:install": "node scripts/security/install-tools.mjs",
    "test:clean-dist": "node --test scripts/clean-package-dist.test.mjs",
    "test:public-readiness": "node --test --test-concurrency=1 scripts/public-readiness/*.test.mjs",
    "test:security": "node --test scripts/security/*.test.mjs",
  }),
  "apps/sso": Object.freeze({
    build: "node ../../scripts/clean-package-dist.mjs && vite build && node scripts/remove-built-dev-vars.mjs",
    "cf-typegen": "wrangler types --strict-vars false",
    check: "pnpm typecheck && pnpm test && pnpm build",
    test: "vitest run",
    typecheck: "pnpm cf-typegen && pnpm typecheck:raw",
    "typecheck:raw": "tsc --build --pretty false",
  }),
  "apps/test-rp": Object.freeze({
    build: "node ../../scripts/clean-package-dist.mjs && wrangler deploy --dry-run --outdir dist",
    "cf-typegen": "wrangler types --strict-vars false",
    check: "pnpm typecheck && pnpm test && pnpm build",
    test: "vitest run",
    typecheck: "pnpm cf-typegen && pnpm typecheck:raw",
    "typecheck:raw": "tsc --noEmit --pretty false",
  }),
  wiki: Object.freeze({
    build: "vitepress build .",
    check: "pnpm run test && pnpm run build && node scripts/validate-build.mjs",
    test: "node --test scripts/summary.test.mjs",
  }),
});
const codeOwnedPackageScripts = Object.freeze({
  ".": Object.freeze({
    build: "pnpm -r --if-present build",
    check: "pnpm test:clean-dist && pnpm test:public-readiness && pnpm --filter @pg72/id check && pnpm --filter @pg72/test-rp check && pnpm --filter @pg72/wiki check",
    "dast:local": "node scripts/security/dast-local.mjs",
    "dast:preview": "node scripts/security/dast.mjs --preview",
    dev: "pnpm --filter @pg72/id dev",
    "dev:rp": "pnpm --filter @pg72/test-rp dev",
    "dev:wiki": "pnpm --filter @pg72/wiki dev",
    "public-readiness:continuity:local": "node scripts/public-readiness/continuity-local.mjs",
    "public-readiness:drills:local": "node scripts/public-readiness/drills-local.mjs",
    "security:artifact": "node scripts/security/artifact-gate.mjs",
    "security:audit": "node scripts/security/accepted-advisories.mjs",
    "security:check": "pnpm test:security && pnpm security:static && pnpm security:secrets && pnpm security:config && pnpm security:audit && pnpm security:artifact && pnpm security:inventory",
    "security:config": "node scripts/security/workflow-config.mjs && node scripts/security/wrangler-config.mjs",
    "security:inventory": "node scripts/security/dependency-inventory.mjs",
    "security:secrets": "node scripts/security/secret-scan.mjs",
    "security:static": "oxlint --type-aware apps/sso/worker apps/test-rp/worker",
    "security:tools:install": "node scripts/security/install-tools.mjs",
    test: "pnpm -r --if-present test",
    "test:clean-dist": "node --test scripts/clean-package-dist.test.mjs",
    "test:public-readiness": "node --test --test-concurrency=1 scripts/public-readiness/*.test.mjs",
    "test:security": "node --test scripts/security/*.test.mjs",
    typecheck: "pnpm -r --if-present typecheck",
  }),
  "apps/sso": Object.freeze({
    build: "node ../../scripts/clean-package-dist.mjs && vite build && node scripts/remove-built-dev-vars.mjs",
    "cf-typegen": "wrangler types --strict-vars false",
    check: "pnpm typecheck && pnpm test && pnpm build",
    "db:migrate:local": "wrangler d1 migrations apply PG72_ID_DB --local",
    "db:seed-test-rp:local": "wrangler d1 execute PG72_ID_DB --local --file seed/test-rp-client.sql",
    dev: "vite",
    test: "vitest run",
    typecheck: "pnpm cf-typegen && pnpm typecheck:raw",
    "typecheck:raw": "tsc --build --pretty false",
  }),
  "apps/test-rp": Object.freeze({
    build: "node ../../scripts/clean-package-dist.mjs && wrangler deploy --dry-run --outdir dist",
    "cf-typegen": "wrangler types --strict-vars false",
    check: "pnpm typecheck && pnpm test && pnpm build",
    "db:migrate:local": "wrangler d1 migrations apply TEST_RP_DB --local",
    dev: "wrangler dev --port 5174",
    test: "vitest run",
    typecheck: "pnpm cf-typegen && pnpm typecheck:raw",
    "typecheck:raw": "tsc --noEmit --pretty false",
  }),
  wiki: Object.freeze({
    build: "vitepress build .",
    check: "pnpm run test && pnpm run build && node scripts/validate-build.mjs",
    dev: "vitepress dev .",
    preview: "vitepress preview .",
    test: "node --test scripts/summary.test.mjs",
  }),
});
const codeOwnedLeafCommands = Object.freeze([
  "node ../../scripts/clean-package-dist.mjs",
  "node --test scripts/clean-package-dist.test.mjs",
  "node --test --test-concurrency=1 scripts/public-readiness/*.test.mjs",
  "node --test scripts/security/*.test.mjs",
  "node --test scripts/summary.test.mjs",
  "node scripts/remove-built-dev-vars.mjs",
  "node scripts/security/accepted-advisories.mjs",
  "node scripts/security/artifact-gate.mjs",
  "node scripts/security/dast-local.mjs",
  "node scripts/security/dast.mjs --authorize-only --preview",
  "node scripts/security/dast.mjs --preview",
  "node scripts/security/dependency-inventory.mjs",
  "node scripts/security/install-tools.mjs",
  "node scripts/security/release-identity.mjs",
  "node scripts/security/secret-scan.mjs",
  "node scripts/security/workflow-config.mjs",
  "node scripts/security/wrangler-config.mjs",
  "node scripts/validate-build.mjs",
  "oxlint --type-aware apps/sso/worker apps/test-rp/worker",
  "pnpm install --frozen-lockfile",
  "tsc --build --pretty false",
  "tsc --noEmit --pretty false",
  "vite build",
  "vitepress build .",
  "vitest run",
  "wrangler deploy --dry-run --outdir dist",
  "wrangler types --strict-vars false",
]);
const codeOwnedLocalScripts = Object.freeze([
  "apps/sso/scripts/remove-built-dev-vars.mjs",
  "scripts/clean-package-dist.mjs",
  "scripts/clean-package-dist.test.mjs",
  "scripts/public-readiness/*.test.mjs",
  "scripts/security/*.test.mjs",
  "scripts/security/accepted-advisories.mjs",
  "scripts/security/artifact-gate.mjs",
  "scripts/security/dast-local.mjs",
  "scripts/security/dast.mjs",
  "scripts/security/dependency-inventory.mjs",
  "scripts/security/install-tools.mjs",
  "scripts/security/release-identity.mjs",
  "scripts/security/secret-scan.mjs",
  "scripts/security/workflow-config.mjs",
  "scripts/security/wrangler-config.mjs",
  "wiki/scripts/summary.test.mjs",
  "wiki/scripts/validate-build.mjs",
]);
const codeOwnedArtifactUpload = Object.freeze({
  filename: "ci.yml",
  step: "verify:8",
  name: "Upload release assurance inventories",
  uses: "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
  with: Object.freeze({
    name: "release-assurance-${{ github.sha }}",
    path: ".artifacts/release",
    "if-no-files-found": "error",
    "retention-days": 7,
    "include-hidden-files": false,
  }),
});
const codeOwnedEarlyIdentityStep = Object.freeze({
  name: "Verify release identities before setup",
  run: "node scripts/security/release-identity.mjs",
});

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function validateWorkflowFileSet(files) {
  const actual = [...files].sort();
  const expected = Object.keys(codeOwnedWorkflowSourceDigests).sort();
  return JSON.stringify(actual) === JSON.stringify(expected)
    ? []
    : ["workflow file set differs from the code-owned exact set"];
}

export function validateWorkflowSourceIdentity(source, filename) {
  const basename = path.basename(filename);
  const expected = codeOwnedWorkflowSourceDigests[basename];
  if (!expected) return [`${basename} lacks a code-owned raw-byte identity`];
  const bytes = Buffer.isBuffer(source) ? source : Buffer.from(source);
  return sha256(bytes) === expected
    ? []
    : [`${basename} raw-byte identity differs from the code-owned LF-only source`];
}

function forbiddenEnvironmentKey(key) {
  const normalized = key.toUpperCase();
  return (
    normalized.startsWith("CLOUDFLARE_") ||
    normalized.startsWith("CF_") ||
    normalized.startsWith("WRANGLER_") ||
    [
      "BASH_ENV",
      "ENV",
      "GITHUB_ENV",
      "GITHUB_PATH",
      "GITHUB_TOKEN",
      "LD_PRELOAD",
      "NODE_OPTIONS",
      "NODE_PATH",
      "PATH",
      "PNPM_HOME",
    ].includes(normalized) ||
    normalized.startsWith("DYLD_") ||
    normalized.startsWith("LD_") ||
    normalized.startsWith("NPM_CONFIG_") ||
    normalized.startsWith("PNPM_CONFIG_") ||
    normalized.startsWith("YARN_") ||
    /(?:^|_)(?:API_KEY|CREDENTIALS?|PASSWORD|PRIVATE_KEY|SECRET|TOKEN)(?:_|$)/.test(normalized)
  );
}

function environmentValue(policy, key) {
  return policy.exactValues?.[key] ?? policy.safeStaticValues?.[key];
}

function expressionContexts(value) {
  const contexts = [];
  for (const match of value.matchAll(/\$\{\{\s*([^{}]+?)\s*}}/g)) contexts.push(match[1].trim());
  return contexts;
}

function validateEnvironmentPolicyDefinition(environmentPolicy, label) {
  const errors = [];
  if (!environmentPolicy || typeof environmentPolicy !== "object") {
    return [`${label} lacks a code-owned environment policy`];
  }
  const groups = [
    ["exactValues", environmentPolicy.exactValues, codeOwnedExactEnvironmentValues],
    ["safeStaticValues", environmentPolicy.safeStaticValues, codeOwnedStaticEnvironmentValues],
  ];
  for (const [groupName, configured, codeOwned] of groups) {
    if (!configured || typeof configured !== "object" || Array.isArray(configured)) {
      errors.push(`${label} ${groupName} must be a mapping`);
      continue;
    }
    for (const [key, value] of Object.entries(configured)) {
      if (forbiddenEnvironmentKey(key)) {
        errors.push(`${label} environment policy contains a code-owned forbidden key`);
      }
      if (!Object.hasOwn(codeOwned, key)) {
        errors.push(`${label} environment policy key is outside the code-owned allowlist`);
      } else if (value !== codeOwned[key]) {
        errors.push(`${label} environment policy value differs from the code-owned value`);
      }
    }
  }
  const contexts = environmentPolicy.allowedExpressionContexts;
  if (
    !Array.isArray(contexts) ||
    JSON.stringify([...new Set(contexts)].sort()) !==
      JSON.stringify([...codeOwnedExpressionContexts].sort())
  ) {
    errors.push(`${label} expression contexts differ from the code-owned allowlist`);
  }
  for (const [workflowName, scopes] of Object.entries(environmentPolicy.scopes ?? {})) {
    const scopedKeys = [
      ...(scopes.workflow ?? []),
      ...Object.values(scopes.jobs ?? {}).flat(),
      ...Object.values(scopes.steps ?? {}).flat(),
    ];
    for (const key of scopedKeys) {
      if (forbiddenEnvironmentKey(key) || !Object.hasOwn(codeOwnedEnvironmentValues, key)) {
        errors.push(`${label}.${workflowName} scope contains a non-code-owned environment key`);
      }
      if (environmentValue(environmentPolicy, key) === undefined) {
        errors.push(`${label}.${workflowName} scope references an undefined environment key`);
      }
    }
  }
  return [...new Set(errors)];
}

function validateEnvironmentScope(
  environment,
  allowedKeys,
  inheritedKeys,
  label,
  environmentPolicy,
) {
  const errors = [];
  const value = environment ?? {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { errors: [`${label} env must be a mapping`], inherited: new Set(inheritedKeys) };
  }
  const actualKeys = Object.keys(value).sort();
  const expectedKeys = [...allowedKeys].sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    errors.push(`${label} env keys differ from the exact scoped policy`);
  }
  const inherited = new Set(inheritedKeys);
  for (const key of actualKeys) {
    if (inherited.has(key)) errors.push(`${label} env overrides an inherited key`);
    inherited.add(key);
    if (forbiddenEnvironmentKey(key)) {
      errors.push(`${label} env contains a forbidden execution/credential key`);
      continue;
    }
    const actual = value[key];
    const expected = environmentValue(environmentPolicy, key);
    const codeOwnedExpected = codeOwnedEnvironmentValues[key];
    if (typeof actual !== "string") {
      errors.push(`${label} env values must be exact strings`);
      continue;
    }
    if (expected === undefined || actual !== expected) {
      errors.push(`${label} env value differs from the exact key/value policy`);
    }
    if (!Object.hasOwn(codeOwnedEnvironmentValues, key) || actual !== codeOwnedExpected) {
      errors.push(`${label} env value differs from the code-owned key/value allowlist`);
    }
    const contexts = expressionContexts(actual);
    if (/[\r\n]/.test(actual)) errors.push(`${label} env values must be single-line`);
    if (actual.includes("${{") && contexts.length === 0) {
      errors.push(`${label} env contains a malformed expression`);
    }
    for (const context of contexts) {
      if (
        !context.startsWith("vars.") ||
        !environmentPolicy.allowedExpressionContexts.includes(context) ||
        actual !== `\${{ ${context} }}`
      ) {
        errors.push(`${label} env contains a forbidden or interpolated expression context`);
      }
    }
    if (/(?:^|\s)(?:--import|--require|-r)(?:\s|=)|\b(?:DYLD_|LD_PRELOAD|NODE_PATH)\b/i.test(actual)) {
      errors.push(`${label} env contains a dynamic executable preload value`);
    }
  }
  return { errors, inherited };
}

export function validateWorkflowEnvironment(document, filename, policy = workflowPolicy) {
  const basename = path.basename(filename);
  const environmentPolicy = policy.environmentPolicy;
  const scopes = environmentPolicy?.scopes?.[basename];
  const errors = validateEnvironmentPolicyDefinition(environmentPolicy, basename);
  if (!environmentPolicy || !scopes) {
    errors.push(`${basename} lacks an exact environment policy`);
    return [...new Set(errors)];
  }
  const workflow = validateEnvironmentScope(
    document.env,
    scopes.workflow ?? [],
    new Set(),
    `${basename}.workflow`,
    environmentPolicy,
  );
  errors.push(...workflow.errors);
  for (const [jobName, job] of entries(document.jobs)) {
    const jobScope = validateEnvironmentScope(
      job.env,
      scopes.jobs?.[jobName] ?? [],
      workflow.inherited,
      `${basename}.${jobName}`,
      environmentPolicy,
    );
    errors.push(...jobScope.errors);
    for (const [index, step] of (job.steps ?? []).entries()) {
      const stepScope = validateEnvironmentScope(
        step.env,
        scopes.steps?.[`${jobName}:${index}`] ?? [],
        jobScope.inherited,
        `${basename}.${jobName}.steps[${index}]`,
        environmentPolicy,
      );
      errors.push(...stepScope.errors);
    }
  }
  for (const jobName of Object.keys(scopes.jobs ?? {})) {
    if (!document.jobs?.[jobName]) errors.push(`${basename} environment policy names a missing job`);
  }
  return [...new Set(errors)];
}

export function validateEarlyIdentityStep(document, filename) {
  const basename = path.basename(filename);
  const errors = [];
  if (!Object.hasOwn(codeOwnedWorkflowRuns, basename)) {
    return [`${basename} lacks an early identity contract`];
  }
  for (const [jobName, job] of entries(document.jobs)) {
    const steps = job.steps ?? [];
    const identityIndexes = steps
      .map((step, index) => (step.run === codeOwnedEarlyIdentityStep.run ? index : -1))
      .filter((index) => index >= 0);
    if (
      !steps[0]?.uses?.startsWith("actions/checkout@") ||
      identityIndexes.length !== 1 ||
      identityIndexes[0] !== 1
    ) {
      errors.push(`${jobName} must run the early identity check immediately after checkout`);
      continue;
    }
    const identity = steps[1];
    if (
      identity.name !== codeOwnedEarlyIdentityStep.name ||
      identity.run !== codeOwnedEarlyIdentityStep.run ||
      JSON.stringify(Object.keys(identity).sort()) !== JSON.stringify(["name", "run"])
    ) {
      errors.push(`${jobName} early identity step differs from the exact command contract`);
    }
  }
  return errors;
}

export function validateWorkflowDocument(
  document,
  filename,
  toolVersions = tools,
  policy = workflowPolicy,
) {
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
  errors.push(...validateWorkflowEnvironment(document, filename, policy));
  errors.push(...validateEarlyIdentityStep(document, filename));

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
        job.steps?.[1]?.run !== "node scripts/security/release-identity.mjs" ||
        job.steps?.[2]?.run !== "node scripts/security/dast.mjs --authorize-only --preview"
      ) {
        errors.push(
          `${jobName} must run early identity before repository Preview authorization`,
        );
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

function normalizeCommand(value) {
  if (typeof value !== "string") return { errors: ["command must be a string"], value: "" };
  const errors = [];
  if (/[^\t\n\r\x20-\x7e]/.test(value) || /\r(?!\n)/.test(value)) {
    errors.push("contains a forbidden control character");
  }
  return { errors, value: value.replaceAll("\r\n", "\n") };
}

const codeOwnedCommandFragments = new Set([
  ...Object.values(codeOwnedWorkflowRuns).flatMap((commands) => Object.values(commands)),
  ...codeOwnedLeafCommands,
  ...Object.values(codeOwnedPackageScripts).flatMap((scripts) =>
    Object.values(scripts).flatMap((value) => value.split("&&").map((command) => command.trim())),
  ),
]);

export function dangerousCommandErrors(command) {
  const normalized = normalizeCommand(command);
  if (!codeOwnedCommandFragments.has(normalized.value)) {
    normalized.errors.push("is not a code-owned exact command");
  }
  return normalized.errors;
}

function validateCommandPolicyDefinition(policy) {
  const errors = [];
  if (
    JSON.stringify(Object.keys(policy).sort()) !==
    JSON.stringify(["environmentPolicy", "packageRoots", "schemaVersion"])
  ) {
    errors.push("workflow policy top-level keys differ from the code-owned schema");
  }
  if (JSON.stringify(policy.packageRoots) !== JSON.stringify(codeOwnedPackageRoots)) {
    errors.push("packageRoots differ from the code-owned exact roots");
  }
  for (const forbidden of [
    "workflows",
    "approvedPackageScripts",
    "allowedLeafCommands",
    "allowedLocalScripts",
  ]) {
    if (Object.hasOwn(policy, forbidden)) {
      errors.push(`workflow policy must not define commands through ${forbidden}`);
    }
  }
  return errors;
}

export function loadWorkflowCommandContext(root = repoRoot, policy = workflowPolicy) {
  const packagesByRoot = {};
  const packageNameToRoot = {};
  for (const packageRoot of codeOwnedPackageRoots) {
    const manifest = JSON.parse(
      readFileSync(path.join(root, packageRoot, "package.json"), "utf8"),
    );
    packagesByRoot[packageRoot] = { name: manifest.name, scripts: manifest.scripts ?? {} };
    packageNameToRoot[manifest.name] = packageRoot;
  }
  return { policy, packagesByRoot, packageNameToRoot };
}

function localScriptError(command, packageRoot) {
  if (!command.startsWith("node ")) return null;
  const tokens = command.split(/\s+/);
  const scriptIndex =
    tokens[1] === "--test" && tokens[2] === "--test-concurrency=1"
      ? 3
      : tokens[1] === "--test"
        ? 2
        : 1;
  const script = tokens[scriptIndex];
  if (!script || script.startsWith("-")) return `does not name an approved local Node script: ${command}`;
  const resolved = path.posix.normalize(path.posix.join(packageRoot, script));
  const allowed = codeOwnedLocalScripts.some((entry) => exactPattern(entry).test(resolved));
  return allowed ? null : `uses an unapproved local script: ${resolved}`;
}

function expandPackageScriptBody(packageRoot, scriptName, context, state) {
  const key = `${packageRoot}:${scriptName}`;
  state.scripts?.add(key);
  const packageData = context.packagesByRoot[packageRoot];
  const actual = packageData?.scripts?.[scriptName];
  const approved = codeOwnedPackageScripts[packageRoot]?.[scriptName];
  if (typeof actual !== "string") {
    state.errors.push(`missing package script ${key}`);
    return;
  }
  if (approved !== actual) {
    state.errors.push(`package script ${key} differs from the code-owned exact value`);
    return;
  }
  for (const command of actual.split("&&").map((value) => value.trim())) {
    expandCommand(command, packageRoot, context, state);
  }
}

function expandPackageScript(packageRoot, scriptName, context, state) {
  const key = `${packageRoot}:${scriptName}`;
  if (state.stack.includes(key)) {
    state.errors.push(`package script cycle: ${[...state.stack, key].join(" -> ")}`);
    return;
  }
  state.stack.push(key);
  const scripts = context.packagesByRoot[packageRoot]?.scripts ?? {};
  for (const lifecycleName of [`pre${scriptName}`, scriptName, `post${scriptName}`]) {
    if (lifecycleName === scriptName || typeof scripts[lifecycleName] === "string") {
      expandPackageScriptBody(packageRoot, lifecycleName, context, state);
    }
  }
  state.stack.pop();
}

function expandInstallLifecycle(context, state) {
  for (const packageRoot of codeOwnedPackageRoots) {
    const scripts = context.packagesByRoot[packageRoot]?.scripts ?? {};
    for (const lifecycleName of ["preinstall", "install", "postinstall", "prepare"]) {
      if (typeof scripts[lifecycleName] === "string") {
        expandPackageScriptBody(packageRoot, lifecycleName, context, state);
      }
    }
  }
}

function expandCommand(command, packageRoot, context, state) {
  state.errors.push(...dangerousCommandErrors(command));
  if (!codeOwnedCommandFragments.has(normalizeCommand(command).value)) return;
  if (command === "pnpm install --frozen-lockfile") {
    state.leaves.push(`${packageRoot}:${command}`);
    expandInstallLifecycle(context, state);
    return;
  }
  if (codeOwnedLeafCommands.includes(command)) {
    const localError = localScriptError(command, packageRoot);
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

function reachablePackageScriptSnapshot(context) {
  const state = { errors: [], leaves: [], scripts: new Set(), stack: [] };
  for (const commands of Object.values(codeOwnedWorkflowRuns)) {
    for (const command of Object.values(commands)) {
      expandCommand(command, ".", context, state);
    }
  }
  const snapshot = {};
  for (const key of [...state.scripts].sort()) {
    const separator = key.indexOf(":");
    const packageRoot = key.slice(0, separator);
    const scriptName = key.slice(separator + 1);
    snapshot[packageRoot] ??= {};
    snapshot[packageRoot][scriptName] =
      context.packagesByRoot[packageRoot]?.scripts?.[scriptName] ?? null;
  }
  return { errors: state.errors, scripts: state.scripts, snapshot };
}

export function reachablePackageScriptDigest(context) {
  return sha256(canonicalJson(reachablePackageScriptSnapshot(context).snapshot));
}

export function completePackageScriptDigest(context) {
  const snapshot = {};
  for (const packageRoot of codeOwnedPackageRoots) {
    snapshot[packageRoot] = context.packagesByRoot[packageRoot]?.scripts ?? null;
  }
  return sha256(canonicalJson(snapshot));
}

export function validateCompletePackageScriptIdentity(context) {
  const errors = [];
  if (
    JSON.stringify(Object.keys(context.packagesByRoot).sort()) !==
    JSON.stringify([...codeOwnedPackageRoots].sort())
  ) {
    errors.push("workspace package roots differ from the code-owned exact set");
  }
  if (
    sha256(canonicalJson(codeOwnedPackageScripts)) !==
    codeOwnedCompletePackageScriptDigest
  ) {
    errors.push("code-owned complete package-script definition digest drifted");
  }
  if (completePackageScriptDigest(context) !== codeOwnedCompletePackageScriptDigest) {
    errors.push("complete workspace package-script maps differ from the code-owned contract");
  }
  return errors;
}

export function validateReachablePackageScriptIdentity(context) {
  const errors = [];
  const actual = reachablePackageScriptSnapshot(context);
  errors.push(...actual.errors);
  const expectedKeys = Object.entries(codeOwnedReachablePackageScripts)
    .flatMap(([packageRoot, scripts]) =>
      Object.keys(scripts).map((scriptName) => `${packageRoot}:${scriptName}`),
    )
    .sort();
  const actualKeys = [...actual.scripts].sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    errors.push("reachable package-script names differ from the code-owned exact graph");
  }
  if (
    sha256(canonicalJson(codeOwnedReachablePackageScripts)) !==
    codeOwnedReachablePackageScriptDigest
  ) {
    errors.push("code-owned reachable package-script definition digest drifted");
  }
  if (sha256(canonicalJson(actual.snapshot)) !== codeOwnedReachablePackageScriptDigest) {
    errors.push("reachable package-script name/value digest differs from the code-owned contract");
  }
  return [...new Set(errors)];
}

function stableMapping(value) {
  return JSON.stringify(Object.entries(value ?? {}).sort(([left], [right]) => left.localeCompare(right)));
}

export function validateArtifactUploads(document, filename) {
  const basename = path.basename(filename);
  const errors = [];
  const uploads = [];
  for (const [jobName, job] of entries(document.jobs)) {
    for (const [index, step] of (job.steps ?? []).entries()) {
      if (step.uses?.startsWith("actions/upload-artifact@")) {
        uploads.push({ jobName, index, step });
      }
    }
  }
  if (basename !== codeOwnedArtifactUpload.filename) {
    if (uploads.length > 0) errors.push(`${basename} must not upload release artifacts`);
    return errors;
  }
  if (uploads.length !== 1) {
    errors.push(`${basename} must contain exactly one code-owned release artifact upload`);
    return errors;
  }
  const [{ jobName, index, step }] = uploads;
  if (`${jobName}:${index}` !== codeOwnedArtifactUpload.step) {
    errors.push(`${basename} release artifact upload moved from its exact job/step`);
  }
  if (step.name !== codeOwnedArtifactUpload.name) {
    errors.push(`${basename} release artifact upload name differs from the code-owned value`);
  }
  if (step.uses !== codeOwnedArtifactUpload.uses) {
    errors.push(`${basename} release artifact upload action differs from the code-owned value`);
  }
  if (JSON.stringify(Object.keys(step).sort()) !== JSON.stringify(["name", "uses", "with"])) {
    errors.push(`${basename} release artifact upload step has extra execution controls`);
  }
  if (stableMapping(step.with) !== stableMapping(codeOwnedArtifactUpload.with)) {
    errors.push(`${basename} release artifact upload options differ from the exact contract`);
  }
  return errors;
}

export function validateWorkflowCommands(document, filename, context) {
  const basename = path.basename(filename);
  const errors = [
    ...validateWorkflowEnvironment(document, filename, context.policy),
    ...validateCommandPolicyDefinition(context.policy),
    ...validateCompletePackageScriptIdentity(context),
    ...validateReachablePackageScriptIdentity(context),
    ...validateArtifactUploads(document, filename),
  ];
  const expected = codeOwnedWorkflowRuns[basename];
  if (!expected) return [...new Set([...errors, `${basename} lacks a code-owned command map`])];

  const actual = {};
  for (const [jobName, job] of entries(document.jobs)) {
    for (const [index, step] of (job.steps ?? []).entries()) {
      if (typeof step.run !== "string") continue;
      const key = `${jobName}:${index}`;
      const normalized = normalizeCommand(step.run);
      errors.push(...normalized.errors.map((error) => `${jobName}.steps[${index}] ${error}`));
      actual[key] = normalized.value;
    }
  }
  if (stableMapping(actual) !== stableMapping(expected)) {
    errors.push(`${basename} job/step run map differs from the code-owned exact map`);
  }

  for (const [key, command] of Object.entries(expected)) {
    if (actual[key] !== command) continue;
    const [jobName, index] = key.split(":");
    const label = `${jobName}.steps[${index}]`;
    const state = { errors: [], leaves: [], stack: [] };
    expandCommand(command, ".", context, state);
    errors.push(...state.errors.map((error) => `${label} ${error}`));
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
  const errors = [...validateWorkflowFileSet(files)];
  if (workflowPolicy.schemaVersion !== 2) errors.push("workflow policy schemaVersion must be 2");
  if (dastPolicy.schemaVersion !== 2) errors.push("DAST policy schemaVersion must be 2");
  if (JSON.stringify(dastPolicy.preview.approvedActors) !== JSON.stringify(["PGpenguin72"])) {
    errors.push("DAST policy approved actors must be exactly PGpenguin72");
  }
  if (dastPolicy.preview.defaultRef !== "refs/heads/main") {
    errors.push("DAST policy default ref must be refs/heads/main");
  }
  const commandContext = loadWorkflowCommandContext();
  errors.push(...validateCompletePackageScriptIdentity(commandContext));
  for (const name of files) {
    const filename = path.join(workflowDirectory, name);
    const source = readFileSync(filename);
    const identityErrors = validateWorkflowSourceIdentity(source, filename);
    errors.push(...identityErrors.map((error) => `${name}: ${error}`));
    if (identityErrors.length > 0) continue;
    const document = YAML.parse(source.toString("utf8"));
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

  const uniqueErrors = [...new Set(errors)];
  assert.deepEqual(uniqueErrors, [], uniqueErrors.join("\n"));
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
