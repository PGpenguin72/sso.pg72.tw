import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { validateReleaseIdentity } from "./release-identity.mjs";

const sourceRoot = fileURLToPath(new URL("../../", import.meta.url));
const identityFiles = [
  ".github/workflows/ci.yml",
  ".github/workflows/dast-preview.yml",
  "package.json",
  "apps/sso/package.json",
  "apps/test-rp/package.json",
  "wiki/package.json",
  "pnpm-workspace.yaml",
  "scripts/security/release-identity.mjs",
];

function fixture(context) {
  const root = mkdtempSync(path.join(os.tmpdir(), "pgid-release-identity-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  for (const relative of identityFiles) {
    const target = path.join(root, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    copyFileSync(path.join(sourceRoot, relative), target);
  }
  return root;
}

function mutateManifest(root, relative, mutate) {
  const filename = path.join(root, relative);
  const manifest = JSON.parse(readFileSync(filename, "utf8"));
  mutate(manifest.scripts);
  writeFileSync(filename, `${JSON.stringify(manifest, null, 2)}\n`);
}

test("accepts the exact checkout before dependencies exist", (context) => {
  const root = fixture(context);
  assert.deepEqual(validateReleaseIdentity(root), []);
  assert.equal(existsSync(path.join(root, "node_modules")), false);
});

test("rejects implicit pre/post hooks at root and filtered workspaces", (context) => {
  for (const relative of ["package.json", "apps/sso/package.json"]) {
    for (const hook of ["precheck", "postcheck"]) {
      const root = fixture(context);
      mutateManifest(root, relative, (scripts) => {
        scripts[hook] = "node scripts/unreviewed.mjs";
      });
      assert.ok(
        validateReleaseIdentity(root).some((error) =>
          error.includes("complete scripts map"),
        ),
        `${relative}:${hook}`,
      );
    }
  }
});

test("rejects every install lifecycle at root and filtered workspaces", (context) => {
  for (const relative of ["package.json", "apps/test-rp/package.json"]) {
    for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
      const root = fixture(context);
      mutateManifest(root, relative, (scripts) => {
        scripts[hook] = "node scripts/unreviewed.mjs";
      });
      assert.ok(
        validateReleaseIdentity(root).some((error) =>
          error.includes("complete scripts map"),
        ),
        `${relative}:${hook}`,
      );
    }
  }
});

test("rejects unrelated extra package scripts", (context) => {
  const root = fixture(context);
  mutateManifest(root, "wiki/package.json", (scripts) => {
    scripts.unreviewed = "node scripts/unreviewed.mjs";
  });
  assert.ok(
    validateReleaseIdentity(root).some((error) =>
      error.includes("complete scripts map"),
    ),
  );
});

test("rejects early identity step removal and reordering", (context) => {
  const block = [
    "      - name: Verify release identities before setup",
    "        run: node scripts/security/release-identity.mjs",
    "",
  ].join("\n");
  for (const mutation of [
    (source) => source.replace(block, ""),
    (source) => source.replace(block, "").replace(
      "      - name: Set up Node.js\n",
      `${block}      - name: Set up Node.js\n`,
    ),
  ]) {
    const root = fixture(context);
    const filename = path.join(root, ".github/workflows/ci.yml");
    const source = readFileSync(filename, "utf8");
    const changed = mutation(source);
    assert.notEqual(changed, source);
    writeFileSync(filename, changed);
    assert.ok(
      validateReleaseIdentity(root).some((error) =>
        error.includes("raw-byte identity"),
      ),
    );
  }
});

test("rejects pnpm workspace lifecycle and build-policy drift", (context) => {
  const root = fixture(context);
  const filename = path.join(root, "pnpm-workspace.yaml");
  writeFileSync(
    filename,
    `${readFileSync(filename, "utf8")}onlyBuiltDependencies:\n  - unreviewed\n`,
  );
  assert.ok(
    validateReleaseIdentity(root).some((error) =>
      error.includes("lifecycle/build policy"),
    ),
  );
});

test("uses only Node standard-library imports and runs without node_modules", (context) => {
  const source = readFileSync(
    path.join(sourceRoot, "scripts/security/release-identity.mjs"),
    "utf8",
  );
  const imports = [...source.matchAll(/from\s+["']([^"']+)["']/g)].map(
    (match) => match[1],
  );
  assert.ok(imports.length > 0);
  assert.ok(imports.every((specifier) => specifier.startsWith("node:")));

  const root = fixture(context);
  const emptyModules = path.join(root, "empty-node-path");
  mkdirSync(emptyModules);
  const result = spawnSync(
    process.execPath,
    [path.join(root, "scripts/security/release-identity.mjs")],
    {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, NODE_PATH: emptyModules },
    },
  );
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.equal(existsSync(path.join(root, "node_modules")), false);
});
