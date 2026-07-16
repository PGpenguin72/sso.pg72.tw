import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const cleanScript = fileURLToPath(
  new URL("./clean-package-dist.mjs", import.meta.url),
);

test("clean-package-dist removes only the package dist directory", async () => {
  const packageRoot = await mkdtemp(join(tmpdir(), "pg72-clean-dist-"));
  const distDirectory = join(packageRoot, "dist");
  const keepFile = join(packageRoot, "keep.txt");
  const sentinel = join(distDirectory, "nested", "stale-sentinel.txt");

  try {
    await mkdir(join(distDirectory, "nested"), { recursive: true });
    await Promise.all([
      writeFile(keepFile, "keep\n"),
      writeFile(sentinel, "stale\n"),
    ]);

    await execFileAsync(process.execPath, [cleanScript], { cwd: packageRoot });
    await assert.rejects(access(distDirectory), { code: "ENOENT" });
    assert.equal(await readFile(keepFile, "utf8"), "keep\n");

    // A package without a dist directory is also a valid clean starting state.
    await execFileAsync(process.execPath, [cleanScript], { cwd: packageRoot });
  } finally {
    await rm(packageRoot, { force: true, recursive: true });
  }
});
