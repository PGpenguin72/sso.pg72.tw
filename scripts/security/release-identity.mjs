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
    fileDigest: "5918fbc11718f01d9298a6c96f5716c202769d3c80b251d005fbb0069db338a9",
    scriptsDigest: "ed08a1eee1e256ba7e382e7a37fb4ac2f2c58c70c152fdb125e1b64691875bdd",
  }),
  "apps/sso": Object.freeze({
    file: "apps/sso/package.json",
    fileDigest: "7211c9c604b39dd42487bd176c8386722ee5e7440269408af1c1b6d5614c5bf3",
    scriptsDigest: "5748888518b3a23655d9dfe1cf7e47df612256770bfff240746e2d16299eae5c",
  }),
  "apps/test-rp": Object.freeze({
    file: "apps/test-rp/package.json",
    fileDigest: "ec8c0e2dd637f450dbcc683ccace0d630125aa620fe8a7ca05f1baa26136f033",
    scriptsDigest: "27f7ead993f9e39bbe49e0df769eefd977be898a52d0e55f57175a29fbbf1af8",
  }),
  wiki: Object.freeze({
    file: "wiki/package.json",
    fileDigest: "042b0edf8684219d27eb00e1a0c37b9d59b3d4b7df0976e0fb3c5488dffac75e",
    scriptsDigest: "adb8061faabcece6e39a9fbe942491e3c4137dd03518ee2a85986b9a73af60b0",
  }),
});

const pnpmWorkspaceContract = Object.freeze({
  file: "pnpm-workspace.yaml",
  digest: "df1b9fbd1c6221aa62320fd090c5cadcbc335b27876fde1a05ab26932eb4dc59",
});

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
  return [...new Set(errors)];
}

function main() {
  const errors = validateReleaseIdentity();
  if (errors.length > 0) {
    console.error(`Early release identity check failed:\n${errors.join("\n")}`);
    process.exitCode = 1;
    return;
  }
  console.log("Early release identity check passed (2 workflows, 4 manifests, pnpm policy).");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
