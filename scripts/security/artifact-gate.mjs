import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const policy = JSON.parse(
  readFileSync(new URL("../../security/release-policy.json", import.meta.url), "utf8"),
);

const forbiddenContent = [
  { name: "private machine path", pattern: /(?:\/Users\/|\/private\/(?:tmp|var)\/|\/home\/(?:runner|[^/\s]+)\/|[A-Za-z]:\\Users\\)/ },
  { name: "source map reference", pattern: /(?:sourceMappingURL|"sourcesContent"\s*:)/ },
  { name: "private key", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: "GitHub token", pattern: /(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}/ },
  { name: "Google API key", pattern: /AIza[0-9A-Za-z_-]{30,}/ },
  {
    name: "assigned secret value",
    pattern:
      /(?:BETTER_AUTH_SECRET|GOOGLE_CLIENT_SECRET|CLOUDFLARE_API_TOKEN)\s*[:=]\s*["'][^"']{8,}["']/,
  },
];

function scrubbedEnvironment() {
  const environment = {
    ...process.env,
    NO_COLOR: "1",
    WRANGLER_SEND_METRICS: "false",
  };
  for (const key of Object.keys(environment)) {
    if (
      /^(?:CLOUDFLARE_|WRANGLER_OAUTH_TOKEN$)/.test(key) ||
      /(?:_SECRET|_TOKEN|_PRIVATE_KEY|_PASSWORD|_CREDENTIAL|_API_KEY)$/.test(key) ||
      ["GOOGLE_CLIENT_ID", "BOOTSTRAP_ADMIN_EMAIL"].includes(key)
    ) {
      delete environment[key];
    }
  }
  return environment;
}

function walk(directory, prefix = "") {
  const files = [];
  for (const name of readdirSync(directory).sort()) {
    const absolute = path.join(directory, name);
    const relative = prefix ? `${prefix}/${name}` : name;
    const stat = lstatSync(absolute);
    assert.ok(!stat.isSymbolicLink(), `artifact symlink is forbidden: ${relative}`);
    if (stat.isDirectory()) files.push(...walk(absolute, relative));
    else if (stat.isFile()) files.push({ absolute, relative, size: stat.size });
    else throw new Error(`unexpected artifact node: ${relative}`);
  }
  return files;
}

export function validateArtifactFiles(directory, filePolicy) {
  const files = walk(directory);
  assert.ok(files.some((file) => file.relative === filePolicy.entrypoint), `missing ${filePolicy.entrypoint}`);
  const allowed = filePolicy.allowedFiles.map((pattern) => new RegExp(`^(?:${pattern})$`));
  let totalBytes = 0;
  const inventory = [];
  for (const file of files) {
    assert.ok(allowed.some((pattern) => pattern.test(file.relative)), `unexpected artifact file: ${file.relative}`);
    assert.ok(!/(?:^|\/)(?:\.dev\.vars(?:\..*)?|\.env(?:\..*)?|[^/]+\.(?:map|pem|key|p8))$/.test(file.relative));
    totalBytes += file.size;
    const bytes = readFileSync(file.absolute);
    if (!file.relative.endsWith(".woff2")) {
      assert.ok(!bytes.includes(0), `unexpected binary content: ${file.relative}`);
      const text = bytes.toString("utf8");
      for (const forbidden of forbiddenContent) {
        assert.ok(!forbidden.pattern.test(text), `${file.relative} contains ${forbidden.name}`);
      }
    }
    inventory.push({
      path: file.relative,
      bytes: file.size,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
  }
  assert.ok(totalBytes <= filePolicy.maxTotalBytes, `artifact is ${totalBytes} bytes (limit ${filePolicy.maxTotalBytes})`);
  if (filePolicy.maxEntrypointBytes) {
    const entrypoint = files.find((file) => file.relative === filePolicy.entrypoint);
    assert.ok(entrypoint.size <= filePolicy.maxEntrypointBytes, `entrypoint is ${entrypoint.size} bytes`);
  }
  return { totalBytes, files: inventory };
}

function names(values, key) {
  return (values ?? []).map((value) => value[key]).sort();
}

export function validateDeploymentConfig(config) {
  const expected = policy.productionWorker;
  assert.equal(config.name, expected.name);
  assert.equal(config.main, policy.artifact.entrypoint);
  assert.deepEqual(config.routes, [{ pattern: expected.route, custom_domain: true }]);
  assert.deepEqual(config.compatibility_flags, ["nodejs_compat"]);
  assert.deepEqual(config.vars, expected.vars);
  assert.equal(config.assets?.binding, "ASSETS");
  assert.equal(config.assets?.directory, "../client");
  assert.equal(config.assets?.run_worker_first, true);
  assert.deepEqual(names(config.d1_databases, "binding"), [...expected.d1Bindings].sort());
  assert.deepEqual(names(config.queues?.producers, "binding"), [...expected.queueBindings].sort());
  assert.deepEqual(names(config.ratelimits, "name"), [...expected.rateLimitBindings].sort());
  assert.deepEqual([...(config.secrets?.required ?? [])].sort(), [...expected.requiredSecrets].sort());
  assert.equal(path.basename(config.configPath), "wrangler.jsonc");
  assert.equal(path.basename(config.userConfigPath), "wrangler.jsonc");
  assert.equal(config.no_bundle, true);
}

function runDryRun(outDirectory) {
  const config = path.join(repoRoot, "apps", "sso", "dist", "pg72_id", "wrangler.json");
  assert.ok(lstatSync(config).isFile(), "production build config is missing; run the SSO build first");
  const result = spawnSync(
    "pnpm",
    [
      "--filter",
      "@pg72/id",
      "exec",
      "wrangler",
      "deploy",
      "--dry-run",
      "--outdir",
      outDirectory,
      "--config",
      "dist/pg72_id/wrangler.json",
    ],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: scrubbedEnvironment(),
      maxBuffer: 20 * 1024 * 1024,
    },
  );
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `Wrangler dry-run failed:\n${result.stdout}${result.stderr}`);
  assert.match(result.stdout + result.stderr, /--dry-run: exiting now\./);
}

function runBuild() {
  const result = spawnSync("pnpm", ["--filter", "@pg72/id", "build"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: scrubbedEnvironment(),
    maxBuffer: 20 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `production build failed:\n${result.stdout}${result.stderr}`);
}

function main() {
  const artifacts = path.join(repoRoot, ".artifacts");
  const workerDirectory = path.join(artifacts, "worker-dry-run");
  const releaseDirectory = path.join(artifacts, "release");
  rmSync(workerDirectory, { force: true, recursive: true });
  mkdirSync(workerDirectory, { recursive: true });
  mkdirSync(releaseDirectory, { recursive: true });
  runBuild();
  runDryRun(workerDirectory);

  const deploymentConfigPath = path.join(repoRoot, "apps", "sso", "dist", "pg72_id", "wrangler.json");
  const deploymentConfig = JSON.parse(readFileSync(deploymentConfigPath, "utf8"));
  validateDeploymentConfig(deploymentConfig);
  const worker = validateArtifactFiles(workerDirectory, policy.artifact);
  const staticAssets = validateArtifactFiles(
    path.join(repoRoot, "apps", "sso", "dist", "client"),
    policy.staticAssets,
  );
  const inventory = {
    schemaVersion: 1,
    worker: policy.productionWorker.name,
    compatibilityDate: deploymentConfig.compatibility_date,
    bindings: {
      d1: names(deploymentConfig.d1_databases, "binding"),
      queues: names(deploymentConfig.queues?.producers, "binding"),
      rateLimits: names(deploymentConfig.ratelimits, "name"),
      secrets: [...deploymentConfig.secrets.required].sort(),
      vars: Object.keys(deploymentConfig.vars).sort(),
    },
    workerModules: worker,
    staticAssets,
  };
  writeFileSync(
    path.join(releaseDirectory, "worker-artifact-inventory.json"),
    `${JSON.stringify(inventory, null, 2)}\n`,
    { mode: 0o600 },
  );
  console.log(
    `Worker artifact gate passed (${worker.files.length} modules/${worker.totalBytes} bytes; ` +
      `${staticAssets.files.length} static assets/${staticAssets.totalBytes} bytes).`,
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`Worker artifact gate failed: ${error.message}`);
    process.exitCode = 1;
  }
}
