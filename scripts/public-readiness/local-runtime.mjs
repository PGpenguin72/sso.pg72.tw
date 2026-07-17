import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { authorizeOwnedLocalOrigin } from "./policy.mjs";

export const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
export const ssoRoot = path.join(repoRoot, "apps", "sso");
export const testRpRoot = path.join(repoRoot, "apps", "test-rp");
const wranglerExecutable = path.join(ssoRoot, "node_modules", ".bin", "wrangler");

function safePath() {
  return process.env.PATH || "/usr/local/bin:/usr/bin:/bin";
}

export function closedChildEnvironment(homeDirectory) {
  return {
    CI: "1",
    HOME: homeDirectory,
    LANG: "C.UTF-8",
    NO_COLOR: "1",
    PATH: safePath(),
    TMPDIR: process.env.TMPDIR || "/tmp",
    WRANGLER_LOG_PATH: path.join(homeDirectory, "wrangler.log"),
    WRANGLER_SEND_METRICS: "false",
  };
}

function boundedDiagnostic(value, sensitiveValues = []) {
  let result = String(value ?? "").slice(-40_000);
  for (const sensitive of sensitiveValues) {
    if (sensitive) result = result.replaceAll(sensitive, "[REDACTED]");
  }
  result = result.replace(
    /(?:CLOUDFLARE|WRANGLER)_[A-Z0-9_]+\s*[=:]\s*\S+/gi,
    "[REDACTED_CREDENTIAL_BINDING]",
  );
  return result;
}

export function runLocalCommand(
  executable,
  args,
  {
    cwd = repoRoot,
    environment,
    label = path.basename(executable),
    suppressDiagnostic = false,
    sensitiveValues = [],
  } = {},
) {
  const result = spawnSync(executable, args, {
    cwd,
    encoding: "utf8",
    env: environment,
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.error) throw new Error(`${label} could not start: ${result.error.name}`);
  if (result.status !== 0) {
    const diagnostic = suppressDiagnostic
      ? "command output suppressed by the closed-data policy"
      : boundedDiagnostic(
          `${result.stdout ?? ""}\n${result.stderr ?? ""}`,
          sensitiveValues,
        );
    throw new Error(`${label} failed locally (${result.status})\n${diagnostic}`);
  }
  return result.stdout ?? "";
}

export function runWrangler(projectDirectory, args, options = {}) {
  return runLocalCommand(
    wranglerExecutable,
    [...args, "--config", path.join(projectDirectory, "wrangler.jsonc")],
    {
      ...options,
      cwd: projectDirectory,
      environment:
        options.environment ?? closedChildEnvironment(projectDirectory),
      label: options.label ?? `wrangler ${args.slice(0, 2).join(" ")}`,
      suppressDiagnostic: options.suppressDiagnostic ?? true,
    },
  );
}

export function runWorkspaceBinary(packageRoot, binary, args, options = {}) {
  return runLocalCommand(
    path.join(packageRoot, "node_modules", ".bin", binary),
    args,
    {
      ...options,
      cwd: packageRoot,
      environment:
        options.environment ?? closedChildEnvironment(options.homeDirectory ?? packageRoot),
      label: options.label ?? `${path.basename(packageRoot)} ${binary}`,
    },
  );
}

export function createLocalProject(
  projectDirectory,
  operation,
  {
    betterAuthSecret,
    bootstrapAdminEmail = "continuity-admin@example.invalid",
  },
) {
  const origin = authorizeOwnedLocalOrigin(operation);
  mkdirSync(projectDirectory, { mode: 0o700, recursive: true });
  const port = Number(new URL(origin).port);
  const configuration = {
    $schema: path.join(ssoRoot, "node_modules", "wrangler", "config-schema.json"),
    name: `pg72-id-${operation}-local`,
    main: path.join(ssoRoot, "worker", "index.ts"),
    compatibility_date: "2026-07-15",
    compatibility_flags: ["nodejs_compat"],
    d1_databases: [
      {
        binding: "PG72_ID_DB",
        database_name: `pg72-id-${operation}-local`,
        database_id: "00000000-0000-0000-0000-000000000091",
        migrations_dir: path.join(ssoRoot, "migrations"),
      },
    ],
    ratelimits: [
      { name: "AUTH_RATE_LIMITER", namespace_id: "9101", simple: { limit: 1000, period: 60 } },
      { name: "ADMIN_RATE_LIMITER", namespace_id: "9102", simple: { limit: 1000, period: 60 } },
      { name: "REGISTRATION_RATE_LIMITER", namespace_id: "9103", simple: { limit: 1000, period: 60 } },
      { name: "INTROSPECTION_IP_RATE_LIMITER", namespace_id: "9104", simple: { limit: 1000, period: 60 } },
      { name: "INTROSPECTION_CLIENT_RATE_LIMITER", namespace_id: "9105", simple: { limit: 1000, period: 60 } },
    ],
    queues: {
      producers: [
        { binding: "SECURITY_EVENTS", queue: `pg72-id-${operation}-security-local` },
        { binding: "LOGOUT_DELIVERIES", queue: `pg72-id-${operation}-logout-local` },
      ],
    },
    vars: {
      AUTH_BASE_URL: origin,
      PASSKEY_RP_ID: "127.0.0.1",
      PASSKEY_ORIGIN: origin,
      PASSKEY_STEP_UP_MAX_AGE_SECONDS: "600",
      REGISTRATION_MODE: "invite",
      ENVIRONMENT: "development",
    },
    secrets: {
      required: [
        "BETTER_AUTH_SECRET",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "BOOTSTRAP_ADMIN_EMAIL",
      ],
    },
  };
  writeFileSync(
    path.join(projectDirectory, "wrangler.jsonc"),
    `${JSON.stringify(configuration, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
  const googleSecret = crypto.randomUUID().replaceAll("-", "");
  const variables = [
    `BETTER_AUTH_SECRET=${betterAuthSecret}`,
    "GOOGLE_CLIENT_ID=local-public-readiness-client",
    `GOOGLE_CLIENT_SECRET=${googleSecret}`,
    `BOOTSTRAP_ADMIN_EMAIL=${bootstrapAdminEmail}`,
  ].join("\n");
  const variablesPath = path.join(projectDirectory, ".dev.vars");
  writeFileSync(variablesPath, `${variables}\n`, { encoding: "utf8", mode: 0o600 });
  chmodSync(variablesPath, 0o600);
  return { origin, port, sensitiveValues: [betterAuthSecret, googleSecret] };
}

export async function assertPortAvailable(origin) {
  const { hostname, port } = new URL(origin);
  assert.equal(hostname, "127.0.0.1");
  await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(Number(port), hostname, () => server.close(resolve));
  });
}

export function startLocalWorker(projectDirectory, runtime) {
  const child = spawn(
    wranglerExecutable,
    [
      "dev",
      "--local",
      "--ip",
      "127.0.0.1",
      "--port",
      String(runtime.port),
      "--inspector-port",
      "0",
      "--persist-to",
      path.join(projectDirectory, ".wrangler", "state"),
      "--config",
      path.join(projectDirectory, "wrangler.jsonc"),
      "--log-level",
      "warn",
      "--show-interactive-dev-session",
      "false",
    ],
    {
      cwd: projectDirectory,
      detached: process.platform !== "win32",
      env: closedChildEnvironment(projectDirectory),
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "";
  const collect = (chunk) => {
    output = `${output}${chunk}`.slice(-40_000);
  };
  child.stdout.on("data", collect);
  child.stderr.on("data", collect);
  return {
    child,
    diagnostic: () => boundedDiagnostic(output, runtime.sensitiveValues),
  };
}

export async function stopLocalWorker(processState) {
  if (!processState) return true;
  const child = processState.child;
  if (child.exitCode !== null || child.signalCode !== null) return true;
  const signal = (name) => {
    try {
      if (process.platform === "win32") child.kill(name);
      else process.kill(-child.pid, name);
    } catch {
      // The process may have exited after the state check.
    }
  };
  signal("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 5_000)),
  ]);
  if (child.exitCode === null && child.signalCode === null) {
    signal("SIGKILL");
    await new Promise((resolve) => child.once("exit", resolve));
  }
  return child.exitCode !== null || child.signalCode !== null;
}

export async function fetchLocal(origin, pathname, init = {}) {
  const base = new URL(origin);
  const target = new URL(pathname, base);
  assert.equal(target.origin, base.origin, "local request escaped its owned origin");
  assert.equal(target.hostname, "127.0.0.1");
  return fetch(target, {
    ...init,
    redirect: "manual",
    signal: init.signal ?? AbortSignal.timeout(5_000),
  });
}

export async function waitForLocalWorker(origin, processState) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (
      processState.child.exitCode !== null ||
      processState.child.signalCode !== null
    ) {
      throw new Error(`local Worker exited before health check\n${processState.diagnostic()}`);
    }
    try {
      const response = await fetchLocal(origin, "/health", {
        signal: AbortSignal.timeout(750),
      });
      if (response.status === 200) return;
    } catch {
      // The fixed loopback listener is not ready yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`local Worker did not become healthy\n${processState.diagnostic()}`);
}

export function removeTemporaryTree(directory) {
  rmSync(directory, { force: true, recursive: true });
}

export function readPackageVersion(packageRoot) {
  return JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8")).version;
}
