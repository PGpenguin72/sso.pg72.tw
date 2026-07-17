import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  closedChildEnvironment,
  createLocalProject,
  fetchLocal,
  inspectSourceState,
  requireCleanSource,
  requireStableSource,
  runLocalCommand,
} from "./local-runtime.mjs";

function git(directory, args) {
  return runLocalCommand("git", args, {
    cwd: directory,
    environment: closedChildEnvironment(directory),
    label: "synthetic Git fixture",
    suppressDiagnostic: true,
  });
}

function sourceRepository() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "pgid-source-state-"));
  git(directory, ["init"]);
  git(directory, ["config", "user.email", "fixture@example.invalid"]);
  git(directory, ["config", "user.name", "Continuity Fixture"]);
  writeFileSync(path.join(directory, ".gitignore"), ".artifacts/\n");
  writeFileSync(path.join(directory, "tracked.txt"), "clean\n");
  git(directory, ["add", ".gitignore", "tracked.txt"]);
  git(directory, ["commit", "-m", "Create fixture"]);
  return directory;
}

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

test("requires an exact clean detached Git source and ignores report artifacts", () => {
  const directory = sourceRepository();
  try {
    git(directory, ["switch", "--detach"]);
    const clean = inspectSourceState({
      repositoryRoot: directory,
      homeDirectory: directory,
    });
    assert.equal(clean.sourceState, "clean");
    assert.match(clean.sourceCommit, /^[a-f0-9]{40}$/);
    assert.doesNotThrow(() => requireCleanSource(clean));

    mkdirSync(path.join(directory, ".artifacts", "public-readiness"), {
      recursive: true,
    });
    writeFileSync(
      path.join(
        directory,
        ".artifacts",
        "public-readiness",
        "continuity-local.json",
      ),
      "{}\n",
    );
    assert.equal(
      inspectSourceState({ repositoryRoot: directory }).sourceState,
      "clean",
    );
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("tracked and untracked source mutations are explicitly dirty", () => {
  for (const mutate of [
    (directory) => writeFileSync(path.join(directory, "tracked.txt"), "dirty\n"),
    (directory) => writeFileSync(path.join(directory, "untracked.txt"), "dirty\n"),
  ]) {
    const directory = sourceRepository();
    try {
      mutate(directory);
      const state = inspectSourceState({ repositoryRoot: directory });
      assert.equal(state.sourceState, "dirty");
      assert.match(state.sourceCommit, /^[a-f0-9]{40}$/);
      assert.throws(() => requireCleanSource(state), /clean Git tree/);
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  }
});

test("Git lookup failure is unavailable and never receives a zero digest", () => {
  const state = inspectSourceState({
    runCommand: () => {
      throw new Error("synthetic command failure");
    },
  });
  assert.deepEqual(state, {
    sourceCommit: null,
    sourceState: "unavailable",
  });
  assert.throws(() => requireCleanSource(state));

  const zero = inspectSourceState({
    runCommand: () => `${"0".repeat(40)}\n`,
  });
  assert.deepEqual(zero, {
    sourceCommit: null,
    sourceState: "unavailable",
  });
  assert.throws(() =>
    requireCleanSource({ sourceCommit: "0".repeat(40), sourceState: "clean" }),
  );
});

test("source attribution must finish at the same clean commit", () => {
  const initial = { sourceCommit: "a".repeat(40), sourceState: "clean" };
  assert.deepEqual(requireStableSource(initial, { ...initial }), initial);
  assert.throws(() =>
    requireStableSource(initial, {
      sourceCommit: "b".repeat(40),
      sourceState: "clean",
    }),
  );
  assert.throws(() =>
    requireStableSource(initial, {
      sourceCommit: initial.sourceCommit,
      sourceState: "dirty",
    }),
  );
  assert.throws(() =>
    requireStableSource(initial, {
      sourceCommit: null,
      sourceState: "unavailable",
    }),
  );
});
