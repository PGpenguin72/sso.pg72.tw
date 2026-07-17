import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const inventory = JSON.parse(
  readFileSync(path.join(root, "security", "secret-inventory.json"), "utf8"),
);

function generatedBindingTypes() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "pgid-secret-inventory-"));
  const output = path.join(directory, "bindings.d.ts");
  const ssoRoot = path.join(root, "apps", "sso");
  try {
    const result = spawnSync(
      path.join(ssoRoot, "node_modules", ".bin", "wrangler"),
      [
        "types",
        output,
        "--include-runtime",
        "false",
        "--strict-vars",
        "false",
        "--config",
        path.join(ssoRoot, "wrangler.jsonc"),
      ],
      {
        cwd: ssoRoot,
        encoding: "utf8",
        env: {
          CI: "1",
          HOME: directory,
          NO_COLOR: "1",
          PATH: process.env.PATH,
          WRANGLER_LOG_PATH: path.join(directory, "wrangler.log"),
          WRANGLER_SEND_METRICS: "false",
        },
      },
    );
    assert.equal(result.status, 0, "Wrangler could not parse the binding contract");
    return readFileSync(output, "utf8");
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
}

test("inventory is names-only, ordered, and uses a closed metadata schema", () => {
  const allowed = [
    "classification",
    "dependencyOrder",
    "name",
    "overlapSupport",
    "owner",
    "rollbackClass",
    "sourceStatus",
    "storageClass",
    "versionField",
  ].sort();
  const names = new Set();
  let previous = 0;
  for (const entry of inventory.entries) {
    assert.deepEqual(Object.keys(entry).sort(), allowed);
    assert.match(entry.name, /^[A-Z][A-Z0-9_]+$/);
    assert.ok(!names.has(entry.name), `duplicate inventory name ${entry.name}`);
    names.add(entry.name);
    assert.ok(entry.dependencyOrder >= previous, "inventory dependency order regressed");
    previous = entry.dependencyOrder;
    assert.ok(!Object.hasOwn(entry, "value"));
  }
});

test("reconciles required Wrangler names and hand-merged optional bindings", () => {
  const byName = new Map(inventory.entries.map((entry) => [entry.name, entry]));
  const bindingTypes = generatedBindingTypes();
  for (const { name } of inventory.entries.filter(
    ({ sourceStatus }) => sourceStatus === "required",
  )) {
    assert.match(bindingTypes, new RegExp(`\\b${name}: string;`));
  }

  const declarations = readFileSync(
    path.join(root, "apps", "sso", "worker", "social-providers.env.d.ts"),
    "utf8",
  );
  const publicDeclarations = readFileSync(
    path.join(root, "apps", "sso", "worker", "public-registration.env.d.ts"),
    "utf8",
  );
  const optional = [
    ...declarations.matchAll(/^\s*([A-Z][A-Z0-9_]+)\??:/gm),
    ...publicDeclarations.matchAll(/^\s*([A-Z][A-Z0-9_]+)\??:/gm),
  ].map((match) => match[1]);
  for (const name of optional) {
    assert.ok(byName.has(name), `optional binding ${name} is absent from inventory`);
  }

  const exampleNames = new Set(
    [...readFileSync(path.join(root, "apps", "sso", ".dev.vars.example"), "utf8").matchAll(/^([A-Z][A-Z0-9_]+)=/gm)].map(
      (match) => match[1],
    ),
  );
  for (const entry of inventory.entries.filter(
    ({ sourceStatus }) => !sourceStatus.startsWith("future-") && sourceStatus !== "external-system-client",
  )) {
    assert.ok(exampleNames.has(entry.name), `${entry.name} is missing from the names-only example contract`);
  }
});

test("reconciles a release-policy secret list when automation is integrated", () => {
  const filename = path.join(root, "security", "release-policy.json");
  if (!existsSync(filename)) return;
  const release = JSON.parse(readFileSync(filename, "utf8"));
  const required = inventory.entries
    .filter(({ sourceStatus }) => sourceStatus === "required")
    .map(({ name }) => name)
    .sort();
  assert.deepEqual(
    release.environments.production.worker.secrets.map(({ name }) => name).sort(),
    required,
  );
});
