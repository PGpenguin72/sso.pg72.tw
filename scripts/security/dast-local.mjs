import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { authorizeDastTarget, fetchOnce, scanLocalRp, scanPgid } from "./dast.mjs";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const ssoOrigin = "http://127.0.0.1:5173";
const rpOrigin = "http://127.0.0.1:5174";

function localEnvironment() {
  const environment = {
    ...process.env,
    CI: "1",
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

function run(args, cwd = repoRoot) {
  const result = spawnSync("pnpm", args, {
    cwd,
    encoding: "utf8",
    env: localEnvironment(),
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `Command failed:\n${result.stdout}${result.stderr}`);
}

async function portAvailable(port) {
  await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => server.close(resolve));
  });
}

function start(args, cwd) {
  const child = spawn("pnpm", args, {
    cwd,
    detached: process.platform !== "win32",
    env: localEnvironment(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  const collect = (chunk) => {
    output = `${output}${chunk}`.slice(-40_000);
  };
  child.stdout.on("data", collect);
  child.stderr.on("data", collect);
  return { child, output: () => output };
}

async function waitForHealth(origin, processState) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (processState.child.exitCode !== null || processState.child.signalCode !== null) {
      throw new Error(
        `local Worker exited early (${processState.child.exitCode ?? processState.child.signalCode}):\n` +
          processState.output(),
      );
    }
    try {
      const response = await fetchOnce(origin, "/health", {
        signal: AbortSignal.timeout(1_000),
      });
      if (response.ok) return;
    } catch {
      // Wrangler has not opened the loopback listener yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`local Worker did not become ready:\n${processState.output()}`);
}

async function stop(processState) {
  if (
    !processState ||
    processState.child.exitCode !== null ||
    processState.child.signalCode !== null
  ) return;
  const signal = (name) => {
    try {
      if (process.platform === "win32") processState.child.kill(name);
      else process.kill(-processState.child.pid, name);
    } catch {
      // The process may have exited between the status check and signal.
    }
  };
  signal("SIGTERM");
  await Promise.race([
    new Promise((resolve) => processState.child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 5_000)),
  ]);
  if (processState.child.exitCode === null && processState.child.signalCode === null) {
    signal("SIGKILL");
  }
}

async function main() {
  assert.deepEqual(authorizeDastTarget(ssoOrigin, {}), { mode: "local", origin: ssoOrigin });
  await Promise.all([portAvailable(5173), portAvailable(5174)]);
  const temporary = mkdtempSync(path.join(os.tmpdir(), "pgid-dast-local-"));
  const ssoState = path.join(temporary, "sso-state");
  const rpState = path.join(temporary, "rp-state");
  mkdirSync(ssoState);
  mkdirSync(rpState);
  let sso;
  let rp;
  try {
    run(["--filter", "@pg72/id", "build"]);
    run(
      [
        "exec",
        "wrangler",
        "d1",
        "migrations",
        "apply",
        "PG72_ID_DB",
        "--local",
        "--persist-to",
        ssoState,
        "--config",
        "wrangler.jsonc",
      ],
      path.join(repoRoot, "apps", "sso"),
    );
    run(
      [
        "exec",
        "wrangler",
        "d1",
        "migrations",
        "apply",
        "TEST_RP_DB",
        "--local",
        "--persist-to",
        rpState,
        "--config",
        "wrangler.jsonc",
      ],
      path.join(repoRoot, "apps", "test-rp"),
    );

    sso = start(
      [
        "exec",
        "wrangler",
        "dev",
        "--local",
        "--ip",
        "127.0.0.1",
        "--port",
        "5173",
        "--inspector-port",
        "0",
        "--persist-to",
        ssoState,
        "--config",
        "dist/pg72_id/wrangler.json",
        "--var",
        `AUTH_BASE_URL:${ssoOrigin}`,
        "--var",
        "PASSKEY_RP_ID:127.0.0.1",
        "--var",
        `PASSKEY_ORIGIN:${ssoOrigin}`,
        "--var",
        "PASSKEY_STEP_UP_MAX_AGE_SECONDS:600",
        "--var",
        "RECOVERY_MODE:disabled",
        "--var",
        "REGISTRATION_MODE:invite",
        "--var",
        "ENVIRONMENT:development",
        "--var",
        "BETTER_AUTH_SECRET:local-dast-placeholder-32-bytes-only",
        "--var",
        "GOOGLE_CLIENT_ID:local-dast-client-id",
        "--var",
        "GOOGLE_CLIENT_SECRET:local-dast-client-secret",
        "--var",
        "BOOTSTRAP_ADMIN_EMAIL:local-dast@example.invalid",
        "--log-level",
        "warn",
        "--show-interactive-dev-session",
        "false",
      ],
      path.join(repoRoot, "apps", "sso"),
    );
    rp = start(
      [
        "exec",
        "wrangler",
        "dev",
        "--local",
        "--ip",
        "127.0.0.1",
        "--port",
        "5174",
        "--inspector-port",
        "0",
        "--persist-to",
        rpState,
        "--config",
        "wrangler.jsonc",
        "--var",
        `OIDC_ISSUER:${ssoOrigin}`,
        "--var",
        "OIDC_CLIENT_ID:pg72-test-rp",
        "--var",
        `RP_BASE_URL:${rpOrigin}`,
        "--var",
        "ENVIRONMENT:development",
        "--log-level",
        "warn",
        "--show-interactive-dev-session",
        "false",
      ],
      path.join(repoRoot, "apps", "test-rp"),
    );

    await Promise.all([waitForHealth(ssoOrigin, sso), waitForHealth(rpOrigin, rp)]);
    const [pgid, testRp] = await Promise.all([scanPgid(ssoOrigin), scanLocalRp(rpOrigin)]);
    const releaseDirectory = path.join(repoRoot, ".artifacts", "release");
    mkdirSync(releaseDirectory, { recursive: true });
    writeFileSync(
      path.join(releaseDirectory, "dast-local-results.json"),
      `${JSON.stringify({ schemaVersion: 1, target: "loopback", pgid, testRp }, null, 2)}\n`,
      { mode: 0o600 },
    );
    console.log(`Local DAST passed (${pgid.length} PGID + ${testRp.length} test RP probes; no credentials).`);
  } finally {
    await Promise.all([stop(rp), stop(sso)]);
    rmSync(temporary, { force: true, recursive: true });
  }
}

main().catch((error) => {
  console.error(`Local DAST failed: ${error.message}`);
  process.exitCode = 1;
});
