import { lstat, readFile, realpath, rm, unlink } from "node:fs/promises";
import { dirname, join, parse } from "node:path";
import { fileURLToPath } from "node:url";

if (process.argv.length !== 2) {
  throw new Error("clean-package-dist does not accept command-line arguments");
}

const scriptPath = await realpath(fileURLToPath(import.meta.url));
const repoRoot = dirname(dirname(scriptPath));
const packageSpecs = [
  ["apps/sso", "@pg72/id"],
  ["apps/test-rp", "@pg72/test-rp"],
];
const allowedPackages = new Map(
  await Promise.all(
    packageSpecs.map(async ([relativePath, packageName]) => [
      await realpath(join(repoRoot, relativePath)),
      packageName,
    ]),
  ),
);

const packageRoot = await realpath(process.cwd());
if (packageRoot === repoRoot || packageRoot === parse(packageRoot).root) {
  throw new Error("clean-package-dist cannot run from a repository or filesystem root");
}

const expectedPackageName = allowedPackages.get(packageRoot);
if (expectedPackageName === undefined) {
  throw new Error(
    "clean-package-dist only runs from the @pg72/id or @pg72/test-rp package root",
  );
}

const packageJson = JSON.parse(
  await readFile(join(packageRoot, "package.json"), "utf8"),
);
if (packageJson.name !== expectedPackageName || packageJson.private !== true) {
  throw new Error(
    `clean-package-dist package identity mismatch: expected ${expectedPackageName}`,
  );
}

const distDirectory = join(packageRoot, "dist");
let distEntry = null;
try {
  distEntry = await lstat(distDirectory);
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}

if (distEntry?.isSymbolicLink()) {
  await unlink(distDirectory);
} else if (distEntry !== null) {
  await rm(distDirectory, { force: true, recursive: true });
}
