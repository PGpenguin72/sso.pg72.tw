import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));

function packageMap(licenseOutput) {
  const packages = new Map();
  for (const [licenseGroup, records] of Object.entries(licenseOutput)) {
    for (const record of records) {
      const license = record.license || licenseGroup;
      assert.ok(license && !/^(?:UNKNOWN|UNLICENSED)$/i.test(license), `${record.name} has no usable license metadata`);
      for (const version of record.versions) {
        const key = `${record.name}@${version}`;
        packages.set(key, {
          name: record.name,
          version,
          license,
          ...(record.homepage ? { homepage: record.homepage } : {}),
        });
      }
    }
  }
  return packages;
}

export function createDependencyInventory(allOutput, productionOutput) {
  const all = packageMap(allOutput);
  const production = packageMap(productionOutput);
  assert.ok(all.size > 0, "dependency inventory is empty");
  return [...all.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => ({ ...value, scope: production.has(key) ? "production" : "development" }));
}

function licenses(args) {
  const result = spawnSync("pnpm", ["licenses", "list", "--json", ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function main() {
  const packageJson = JSON.parse(readFileSync(path.join(repoRoot, "package.json"), "utf8"));
  const packages = createDependencyInventory(licenses([]), licenses(["--prod"]));
  const output = {
    schemaVersion: 1,
    source: "pnpm-lock.yaml",
    packageManager: packageJson.packageManager,
    platform: `${process.platform}-${process.arch}`,
    packages,
  };
  const directory = path.join(repoRoot, ".artifacts", "release");
  mkdirSync(directory, { recursive: true });
  writeFileSync(
    path.join(directory, "dependency-inventory.json"),
    `${JSON.stringify(output, null, 2)}\n`,
    { mode: 0o600 },
  );
  console.log(`Dependency/license inventory generated (${packages.length} package versions).`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`Dependency inventory gate failed: ${error.message}`);
    process.exitCode = 1;
  }
}
