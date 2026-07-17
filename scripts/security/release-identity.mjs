import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));

const workflowDigests = Object.freeze({
  "ci.yml": "eedcbefb68e7d0a4047a0793013545a95387274d608c4840d86e80360e29f7b0",
  "dast-preview.yml": "9826177b4315c8f0ca29fe812508349d1ac0fcab6e3cce9d1e0772c9c124e711",
});

const packageContracts = Object.freeze({
  ".": Object.freeze({
    file: "package.json",
    fileDigest: "cc3718b79507c961a44015abe3e3ad1aca689ec98c0c8b319293cf0b9ef940eb",
    scriptsDigest: "6561b6b949f9b71d0f3ae8b2c0d2d22ece9800f9fc414381db71dd12998a395a",
  }),
  "apps/sso": Object.freeze({
    file: "apps/sso/package.json",
    fileDigest: "7211c9c604b39dd42487bd176c8386722ee5e7440269408af1c1b6d5614c5bf3",
    scriptsDigest: "5748888518b3a23655d9dfe1cf7e47df612256770bfff240746e2d16299eae5c",
  }),
  "apps/test-rp": Object.freeze({
    file: "apps/test-rp/package.json",
    fileDigest: "20f93ab0f93e12cd7ec18c8a3926238e55e5c7bb0f3705797943bea96ce8ed68",
    scriptsDigest: "27f7ead993f9e39bbe49e0df769eefd977be898a52d0e55f57175a29fbbf1af8",
  }),
  wiki: Object.freeze({
    file: "wiki/package.json",
    fileDigest: "042b0edf8684219d27eb00e1a0c37b9d59b3d4b7df0976e0fb3c5488dffac75e",
    scriptsDigest: "adb8061faabcece6e39a9fbe942491e3c4137dd03518ee2a85986b9a73af60b0",
  }),
});

const codeOwnedProjectRoots = Object.freeze(Object.keys(packageContracts));

const pnpmWorkspaceContract = Object.freeze({
  file: "pnpm-workspace.yaml",
  digest: "df1b9fbd1c6221aa62320fd090c5cadcbc335b27876fde1a05ab26932eb4dc59",
});

const pnpmLockfileContract = Object.freeze({
  file: "pnpm-lock.yaml",
  digest: "318d3fb68b15384f374cfb7d4a81b7cec543b1e275aa8b8cd0b5697b0af1dcdc",
});

const patchContracts = Object.freeze({
  "@better-auth__oauth-provider@1.6.23.patch":
    "98ee2635aa622b1dd846c50a6cc414e81b3fa976aeb6499e9dc9581b4faae5bb",
  "README.md": "e1cccd28b6dbf29c2d063645fd3d988113f3bcdaaa28ef4da3c09297f28378e9",
});

const prohibitedWorkspacePnpmfiles = Object.freeze([
  ".pnpmfile.mjs",
  ".pnpmfile.cjs",
]);

const prohibitedProjectNpmrcFiles = Object.freeze(
  codeOwnedProjectRoots.map((projectRoot) =>
    projectRelativePath(projectRoot, ".npmrc"),
  ),
);

const prohibitedProjectBindingGypFiles = Object.freeze(
  codeOwnedProjectRoots.map((projectRoot) =>
    projectRelativePath(projectRoot, "binding.gyp"),
  ),
);

const prohibitedProjectNodeModules = Object.freeze(
  codeOwnedProjectRoots.map((projectRoot) =>
    projectRelativePath(projectRoot, "node_modules"),
  ),
);

function projectRelativePath(projectRoot, relative) {
  return projectRoot === "." ? relative : `${projectRoot}/${relative}`;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function exactRegularFile(root, relative, errors) {
  const filename = path.join(root, relative);
  try {
    const stat = lstatSync(filename);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      errors.push(`${relative} must be a regular non-symlink file`);
      return null;
    }
    return readFileSync(filename);
  } catch {
    errors.push(`${relative} is missing or unreadable`);
    return null;
  }
}

function exactDirectoryFileSet(root, relative, expectedFiles, errors) {
  const dirname = path.join(root, relative);
  let files;
  try {
    const stat = lstatSync(dirname);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      errors.push(`${relative} must be a regular non-symlink directory`);
      return;
    }
    files = readdirSync(dirname).sort();
  } catch {
    errors.push(`${relative} is missing or unreadable`);
    return;
  }
  if (JSON.stringify(files) !== JSON.stringify([...expectedFiles].sort())) {
    errors.push(`${relative} file set differs from the early install-input identity`);
  }
}

function rejectPresentPath(root, relative, description, errors) {
  try {
    lstatSync(path.join(root, relative));
    errors.push(`${relative} is an unreviewed ${description} and must be absent`);
  } catch (error) {
    if (
      !error ||
      typeof error !== "object" ||
      !("code" in error) ||
      error.code !== "ENOENT"
    ) {
      errors.push(`${relative} could not be proven absent`);
    }
  }
}

export function validateReleaseIdentity(root = repoRoot) {
  const errors = [];
  let workflowFiles = [];
  try {
    workflowFiles = readdirSync(path.join(root, ".github", "workflows"), {
      withFileTypes: true,
    })
      .filter((entry) => /\.ya?ml$/.test(entry.name))
      .map((entry) => entry.name)
      .sort();
  } catch {
    errors.push(".github/workflows is missing or unreadable");
  }
  const expectedWorkflowFiles = Object.keys(workflowDigests).sort();
  if (JSON.stringify(workflowFiles) !== JSON.stringify(expectedWorkflowFiles)) {
    errors.push("workflow file set differs from the early code-owned identity");
  }
  for (const [name, digest] of Object.entries(workflowDigests)) {
    const bytes = exactRegularFile(root, `.github/workflows/${name}`, errors);
    if (bytes && sha256(bytes) !== digest) {
      errors.push(`${name} differs from the early code-owned raw-byte identity`);
    }
  }

  for (const contract of Object.values(packageContracts)) {
    const bytes = exactRegularFile(root, contract.file, errors);
    if (!bytes) continue;
    if (sha256(bytes) !== contract.fileDigest) {
      errors.push(`${contract.file} differs from the early manifest identity`);
    }
    try {
      const manifest = JSON.parse(bytes.toString("utf8"));
      if (
        !manifest.scripts ||
        typeof manifest.scripts !== "object" ||
        Array.isArray(manifest.scripts) ||
        sha256(canonicalJson(manifest.scripts)) !== contract.scriptsDigest
      ) {
        errors.push(`${contract.file} complete scripts map differs from the early identity`);
      }
    } catch {
      errors.push(`${contract.file} is not strict JSON`);
    }
  }

  const workspace = exactRegularFile(root, pnpmWorkspaceContract.file, errors);
  if (workspace && sha256(workspace) !== pnpmWorkspaceContract.digest) {
    errors.push("pnpm workspace lifecycle/build policy differs from the early identity");
  }

  const lockfile = exactRegularFile(root, pnpmLockfileContract.file, errors);
  if (lockfile && sha256(lockfile) !== pnpmLockfileContract.digest) {
    errors.push("pnpm-lock.yaml differs from the early frozen-install identity");
  }

  const expectedPatchFiles = Object.keys(patchContracts);
  exactDirectoryFileSet(root, "patches", expectedPatchFiles, errors);
  for (const [name, digest] of Object.entries(patchContracts)) {
    const relative = `patches/${name}`;
    const bytes = exactRegularFile(root, relative, errors);
    if (bytes && sha256(bytes) !== digest) {
      errors.push(`${relative} differs from the early patch identity`);
    }
  }

  for (const relative of prohibitedWorkspacePnpmfiles) {
    rejectPresentPath(root, relative, "workspace pnpm hook", errors);
  }
  for (const relative of prohibitedProjectNpmrcFiles) {
    rejectPresentPath(root, relative, "project pnpm configuration", errors);
  }
  for (const relative of prohibitedProjectBindingGypFiles) {
    rejectPresentPath(root, relative, "implicit native install input", errors);
  }
  for (const relative of prohibitedProjectNodeModules) {
    rejectPresentPath(root, relative, "pre-existing install state", errors);
  }
  return [...new Set(errors)];
}

function main() {
  const errors = validateReleaseIdentity();
  if (errors.length > 0) {
    console.error(`Early release identity check failed:\n${errors.join("\n")}`);
    process.exitCode = 1;
    return;
  }
  console.log(
    "Early release identity check passed (2 workflows, 4 manifests, pnpm policy, lockfile, patch set, no project hooks/config/implicit builds/install state).",
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
