import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { validateReleaseIdentity } from "./release-identity.mjs";

const sourceRoot = fileURLToPath(new URL("../../", import.meta.url));
const codeOwnedProjectRoots = [".", "apps/sso", "apps/test-rp", "wiki"];
const identityFiles = [
  ".github/workflows/ci.yml",
  ".github/workflows/dast-preview.yml",
  "package.json",
  "apps/sso/package.json",
  "apps/test-rp/package.json",
  "wiki/package.json",
  "pnpm-workspace.yaml",
  "pnpm-lock.yaml",
  "patches/@better-auth__oauth-provider@1.6.23.patch",
  "patches/README.md",
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
  for (const projectRoot of codeOwnedProjectRoots) {
    assert.equal(
      existsSync(path.join(root, projectRoot, "node_modules")),
      false,
      projectRoot,
    );
  }
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

test("rejects missing, mutated, and symlinked frozen lockfiles", (context) => {
  for (const [name, mutate] of [
    ["missing", (root, filename) => rmSync(filename)],
    [
      "mutated",
      (root, filename) =>
        writeFileSync(filename, `${readFileSync(filename, "utf8")}# drift\n`),
    ],
    [
      "symlinked",
      (root, filename) => {
        const target = path.join(root, "lockfile-target.yaml");
        renameSync(filename, target);
        symlinkSync(path.basename(target), filename);
      },
    ],
  ]) {
    const root = fixture(context);
    const filename = path.join(root, "pnpm-lock.yaml");
    mutate(root, filename);
    assert.ok(
      validateReleaseIdentity(root).some((error) =>
        error.includes("pnpm-lock.yaml"),
      ),
      name,
    );
  }
});

test("rejects missing, mutated, extra, and symlinked patch inputs", (context) => {
  const patchRelative = "patches/@better-auth__oauth-provider@1.6.23.patch";
  for (const [name, mutate] of [
    ["missing", (root, filename) => rmSync(filename)],
    [
      "mutated",
      (root, filename) =>
        writeFileSync(filename, `${readFileSync(filename, "utf8")}# drift\n`),
    ],
    [
      "extra",
      (root) => writeFileSync(path.join(root, "patches/unreviewed.patch"), "drift\n"),
    ],
    [
      "symlinked",
      (root, filename) => {
        const target = path.join(root, "patch-target.patch");
        renameSync(filename, target);
        symlinkSync("../patch-target.patch", filename);
      },
    ],
  ]) {
    const root = fixture(context);
    mutate(root, path.join(root, patchRelative));
    assert.ok(
      validateReleaseIdentity(root).some((error) => error.includes("patch")),
      name,
    );
  }
});

test("rejects every pnpm 11.5 default workspace hook filename", (context) => {
  for (const relative of [".pnpmfile.mjs", ".pnpmfile.cjs"]) {
    const root = fixture(context);
    writeFileSync(path.join(root, relative), "throw new Error('unreviewed hook')\n");
    assert.ok(
      validateReleaseIdentity(root).some((error) => error.includes(relative)),
      relative,
    );
  }
});

test("rejects project npmrc files at every code-owned package root", (context) => {
  for (const relative of [
    ".npmrc",
    "apps/sso/.npmrc",
    "apps/test-rp/.npmrc",
    "wiki/.npmrc",
  ]) {
    const root = fixture(context);
    writeFileSync(path.join(root, relative), "registry=https://example.invalid/\n");
    assert.ok(
      validateReleaseIdentity(root).some((error) => error.includes(relative)),
      relative,
    );
  }
});

test("rejects every binding.gyp node type at every code-owned package root", (context) => {
  const mutations = [
    ["file", (filename) => writeFileSync(filename, "{}\n")],
    ["directory", (filename) => mkdirSync(filename)],
    ["symlink", (filename) => symlinkSync("missing-binding-target", filename)],
    [
      "unreadable",
      (filename) => {
        writeFileSync(filename, "{}\n");
        chmodSync(filename, 0o000);
      },
    ],
  ];
  for (const projectRoot of codeOwnedProjectRoots) {
    for (const [nodeType, mutate] of mutations) {
      const root = fixture(context);
      const relative =
        projectRoot === "." ? "binding.gyp" : `${projectRoot}/binding.gyp`;
      mutate(path.join(root, relative));
      assert.ok(
        validateReleaseIdentity(root).some((error) => error.includes(relative)),
        `${relative}:${nodeType}`,
      );
    }
  }
});

test("rejects pre-existing node_modules and lifecycle hooks at every package root", (context) => {
  for (const projectRoot of codeOwnedProjectRoots) {
    const root = fixture(context);
    const relative =
      projectRoot === "." ? "node_modules" : `${projectRoot}/node_modules`;
    const hooks = path.join(root, relative, ".hooks");
    mkdirSync(hooks, { recursive: true });
    writeFileSync(path.join(hooks, "install"), "#!/bin/sh\nexit 1\n");
    assert.ok(
      validateReleaseIdentity(root).some((error) => error.includes(relative)),
      relative,
    );
  }
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
