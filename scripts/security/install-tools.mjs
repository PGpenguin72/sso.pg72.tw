import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const manifest = JSON.parse(
  readFileSync(new URL("../../security/tool-versions.json", import.meta.url), "utf8"),
);

async function install(name, config, platformKey, outputDirectory, temporaryDirectory) {
  const asset = config.assets[platformKey];
  assert.ok(asset, `${name} does not publish an asset for ${platformKey}`);
  const releaseBase = config.source.replace("/releases/tag/", "/releases/download/");
  const url = `${releaseBase}/${asset.archive}`;
  const response = await fetch(url, { signal: AbortSignal.timeout(60_000) });
  assert.ok(response.ok, `${name} download failed with HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  const digest = createHash("sha256").update(bytes).digest("hex");
  assert.equal(digest, asset.sha256, `${name} archive checksum mismatch`);

  const archive = path.join(temporaryDirectory, asset.archive);
  writeFileSync(archive, bytes, { mode: 0o600 });
  const extracted = spawnSync("tar", ["-xzf", archive, "-C", outputDirectory, name], {
    encoding: "utf8",
  });
  assert.equal(extracted.status, 0, `${name} extraction failed: ${extracted.stderr}`);
  const executable = path.join(outputDirectory, name);
  chmodSync(executable, 0o755);
  const version = spawnSync(executable, [name === "actionlint" ? "-version" : "version"], {
    encoding: "utf8",
  });
  assert.equal(version.status, 0, `${name} version check failed`);
  assert.match(version.stdout, new RegExp(`(?:^|\\s)${config.version.replaceAll(".", "\\.")}(?:$|\\s)`));
  console.log(`Installed ${name} ${config.version} (${platformKey}, sha256 verified).`);
}

async function main() {
  const platformKey = `${process.platform}-${process.arch}`;
  assert.match(platformKey, /^(?:darwin|linux)-(?:arm64|x64)$/);
  const outputDirectory = path.join(repoRoot, ".security-tools");
  mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
  const temporaryDirectory = mkdtempSync(path.join(os.tmpdir(), "pgid-security-tools-"));
  try {
    for (const [name, config] of Object.entries(manifest.tools)) {
      await install(name, config, platformKey, outputDirectory, temporaryDirectory);
    }
  } finally {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`Security tool installation failed: ${error.message}`);
    process.exitCode = 1;
  });
}
