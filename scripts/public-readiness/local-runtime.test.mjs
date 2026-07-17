import assert from "node:assert/strict";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  closedChildEnvironment,
  createLocalProject,
  fetchLocal,
  runLocalCommand,
} from "./local-runtime.mjs";

test("constructs a credential-free child environment", () => {
  const environment = closedChildEnvironment("/tmp/pgid-closed-home");
  assert.deepEqual(Object.keys(environment).sort(), [
    "CI",
    "HOME",
    "LANG",
    "NO_COLOR",
    "PATH",
    "TMPDIR",
    "WRANGLER_LOG_PATH",
    "WRANGLER_SEND_METRICS",
  ]);
  for (const name of Object.keys(environment)) {
    assert.doesNotMatch(name, /(?:SECRET|TOKEN|CREDENTIAL|API_KEY)/);
  }
});

test("creates only a fixed local Wrangler project and mode-0600 variable file", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "pgid-local-project-"));
  try {
    const runtime = createLocalProject(directory, "continuity", {
      betterAuthSecret: "synthetic-unit-secret-at-least-32-characters",
    });
    const config = JSON.parse(
      readFileSync(path.join(directory, "wrangler.jsonc"), "utf8"),
    );
    assert.equal(runtime.origin, "http://127.0.0.1:5183");
    assert.equal(config.vars.ENVIRONMENT, "development");
    assert.equal(config.vars.AUTH_BASE_URL, runtime.origin);
    assert.equal(config.routes, undefined);
    assert.equal(config.account_id, undefined);
    assert.equal(
      JSON.stringify(config).includes('"remote":true'),
      false,
    );
    const variables = readFileSync(path.join(directory, ".dev.vars"), "utf8")
      .trim()
      .split("\n")
      .map((line) => line.split("=", 1)[0])
      .sort();
    assert.deepEqual(variables, [
      "BETTER_AUTH_SECRET",
      "BOOTSTRAP_ADMIN_EMAIL",
      "GOOGLE_CLIENT_ID",
      "GOOGLE_CLIENT_SECRET",
    ]);
    assert.equal(statSync(path.join(directory, ".dev.vars")).mode & 0o777, 0o600);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("suppresses failed command output and blocks origin escape before fetch", async () => {
  assert.throws(
    () =>
      runLocalCommand(
        process.execPath,
        ["-e", "process.stderr.write('synthetic-sensitive-marker');process.exit(1)"],
        { label: "closed failure", suppressDiagnostic: true },
      ),
    (error) => {
      assert.doesNotMatch(error.message, /synthetic-sensitive-marker/);
      return true;
    },
  );
  await assert.rejects(
    fetchLocal("http://127.0.0.1:5183", "https://example.invalid/escape"),
    /escaped its owned origin/,
  );
});
