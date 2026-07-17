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

import {
  classifyDiagnosticPath,
  diagnosticPath,
  scanBufferForSecrets,
} from "./secret-family.mjs";
import { validateGeneratedSsoConfig } from "./wrangler-config.mjs";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const policy = JSON.parse(
  readFileSync(new URL("../../security/release-policy.json", import.meta.url), "utf8"),
);

const forbiddenContent = [
  { name: "private machine path", pattern: /(?:\/Users\/|\/private\/(?:tmp|var)\/|\/home\/(?:runner|[^/\s]+)\/|[A-Za-z]:\\Users\\)/ },
  { name: "source map reference", pattern: /(?:sourceMappingURL|"sourcesContent"\s*:)/ },
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
  let names;
  try {
    names = readdirSync(directory).sort();
  } catch {
    throw new Error(`unable to read artifact directory: ${diagnosticPath(prefix || ".")}`);
  }
  for (const name of names) {
    const absolute = path.join(directory, name);
    const relative = prefix ? `${prefix}/${name}` : name;
    const classified = classifyDiagnosticPath(relative);
    assert.ok(!classified.unsafe, `unsafe artifact path: ${classified.display}`);
    let stat;
    try {
      stat = lstatSync(absolute);
    } catch {
      throw new Error(`unable to inspect artifact path: ${classified.display}`);
    }
    assert.ok(!stat.isSymbolicLink(), `artifact symlink is forbidden: ${classified.display}`);
    if (stat.isDirectory()) files.push(...walk(absolute, relative));
    else if (stat.isFile()) {
      files.push({
        absolute,
        relative: classified.normalized,
        display: classified.display,
        size: stat.size,
      });
    } else throw new Error(`unexpected artifact node: ${classified.display}`);
  }
  return files;
}

export function validateArtifactFiles(
  directory,
  filePolicy,
  { scanRoot = "artifact:unclassified" } = {},
) {
  const files = walk(directory);
  assert.ok(
    files.some((file) => file.relative === filePolicy.entrypoint),
    `missing ${diagnosticPath(filePolicy.entrypoint)}`,
  );
  const allowed = filePolicy.allowedFiles.map((pattern) => new RegExp(`^(?:${pattern})$`));
  let totalBytes = 0;
  const inventory = [];
  for (const file of files) {
    assert.ok(
      allowed.some((pattern) => pattern.test(file.relative)),
      `unexpected artifact file: ${file.display}`,
    );
    assert.ok(!/(?:^|\/)(?:\.dev\.vars(?:\..*)?|\.env(?:\..*)?|[^/]+\.(?:map|pem|key|p8))$/.test(file.relative));
    totalBytes += file.size;
    let bytes;
    try {
      bytes = readFileSync(file.absolute);
    } catch {
      throw new Error(`unable to read artifact file: ${file.display}`);
    }
    const text = bytes.toString("utf8");
    for (const forbidden of forbiddenContent) {
      assert.ok(!forbidden.pattern.test(text), `${file.display} contains ${forbidden.name}`);
    }
    for (const rule of scanBufferForSecrets(bytes, {
      enforceGeneratedLiteralContract:
        scanRoot === "artifact:worker" && file.relative === filePolicy.entrypoint,
      relativePath: `${scanRoot}/${file.relative}`,
    })) {
      assert.fail(`${file.display} contains redacted secret family [${rule}]`);
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

export function validateDeploymentConfig(config) {
  const errors = validateGeneratedSsoConfig(config, repoRoot);
  assert.deepEqual(errors, [], errors.join("\n"));
}

function runDryRun(outDirectory) {
  const config = path.join(
    repoRoot,
    policy.environments.production.generatedConfig,
  );
  let configStat;
  try {
    configStat = lstatSync(config);
  } catch {
    throw new Error("production build config is missing; run the SSO build first");
  }
  assert.ok(configStat.isFile(), "production build config is missing; run the SSO build first");
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
  if (result.error) throw new Error("unable to execute Wrangler dry-run");
  assert.equal(result.status, 0, "Wrangler dry-run failed; subprocess output is redacted");
  assert.match(result.stdout + result.stderr, /--dry-run: exiting now\./);
}

function runBuild() {
  const result = spawnSync("pnpm", ["--filter", "@pg72/id", "build"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: scrubbedEnvironment(),
    maxBuffer: 20 * 1024 * 1024,
  });
  if (result.error) throw new Error("unable to execute production build");
  assert.equal(result.status, 0, "production build failed; subprocess output is redacted");
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

  const deploymentConfigPath = path.join(
    repoRoot,
    policy.environments.production.generatedConfig,
  );
  const deploymentConfig = JSON.parse(readFileSync(deploymentConfigPath, "utf8"));
  validateDeploymentConfig(deploymentConfig);
  const worker = validateArtifactFiles(workerDirectory, policy.artifact, {
    scanRoot: "artifact:worker",
  });
  const staticAssets = validateArtifactFiles(
    path.join(repoRoot, "apps", "sso", "dist", "client"),
    policy.staticAssets,
    { scanRoot: "artifact:static" },
  );
  const inventory = {
    schemaVersion: 1,
    worker: policy.environments.production.worker.name,
    compatibilityDate: deploymentConfig.compatibility_date,
    bindings: {
      assets: deploymentConfig.assets,
      d1: deploymentConfig.d1_databases,
      queueProducers: deploymentConfig.queues.producers,
      queueConsumers: deploymentConfig.queues.consumers,
      rateLimits: deploymentConfig.ratelimits,
      requiredSecrets: [...deploymentConfig.secrets.required],
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
  } catch {
    console.error("Worker artifact gate failed; diagnostic details are redacted.");
    process.exitCode = 1;
  }
}
