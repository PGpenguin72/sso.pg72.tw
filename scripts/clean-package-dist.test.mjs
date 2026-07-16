import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, parse } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const cleanScript = fileURLToPath(
  new URL("./clean-package-dist.mjs", import.meta.url),
);
const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const packageRoots = [join(repoRoot, "apps/sso"), join(repoRoot, "apps/test-rp")];

async function runCleaner(cwd, args = []) {
  return execFileAsync(process.execPath, [cleanScript, ...args], { cwd });
}

async function expectCleanerFailure(cwd, args, messagePattern) {
  try {
    await runCleaner(cwd, args);
  } catch (error) {
    assert.match(error.stderr, messagePattern);
    return;
  }
  assert.fail("clean-package-dist unexpectedly succeeded");
}

async function assertMissing(path) {
  await assert.rejects(access(path), { code: "ENOENT" });
}

test("clean-package-dist cleans both allowed packages and is idempotent", async (t) => {
  for (const packageRoot of packageRoots) {
    await t.test(packageRoot, async () => {
      const distDirectory = join(packageRoot, "dist");
      const keepFile = join(
        packageRoot,
        `.clean-package-dist-keep-${process.pid}`,
      );
      const sentinel = join(distDirectory, "nested", "stale-sentinel.txt");

      try {
        await rm(distDirectory, { force: true, recursive: true });
        await mkdir(join(distDirectory, "nested"), { recursive: true });
        await Promise.all([
          writeFile(keepFile, "keep\n"),
          writeFile(sentinel, "stale\n"),
        ]);

        await runCleaner(packageRoot);
        await assertMissing(distDirectory);
        assert.equal(await readFile(keepFile, "utf8"), "keep\n");

        await runCleaner(packageRoot);
        await assertMissing(distDirectory);
      } finally {
        await Promise.all([
          rm(distDirectory, { force: true, recursive: true }),
          rm(keepFile, { force: true }),
        ]);
      }
    });
  }
});

test("clean-package-dist rejects a forged package outside the allowlist", async () => {
  const fakePackageRoot = await mkdtemp(join(tmpdir(), "pg72-clean-dist-fake-"));
  const sentinel = join(fakePackageRoot, "dist", "outside-sentinel.txt");

  try {
    await mkdir(join(fakePackageRoot, "dist"));
    await Promise.all([
      writeFile(
        join(fakePackageRoot, "package.json"),
        JSON.stringify({ name: "@pg72/id", private: true }),
      ),
      writeFile(sentinel, "outside\n"),
    ]);

    await expectCleanerFailure(fakePackageRoot, [], /only runs from/);
    assert.equal(await readFile(sentinel, "utf8"), "outside\n");
  } finally {
    await rm(fakePackageRoot, { force: true, recursive: true });
  }
});

test("clean-package-dist rejects repository and filesystem roots", async () => {
  const rootDist = join(repoRoot, "dist");
  const sentinel = join(rootDist, `.clean-package-dist-root-${process.pid}`);
  let createdRootDist = false;

  try {
    try {
      await access(rootDist);
    } catch (error) {
      assert.equal(error.code, "ENOENT");
      await mkdir(rootDist);
      createdRootDist = true;
    }
    await writeFile(sentinel, "root\n");

    await expectCleanerFailure(repoRoot, [], /cannot run from/);
    assert.equal(await readFile(sentinel, "utf8"), "root\n");
    await expectCleanerFailure(parse(repoRoot).root, [], /cannot run from/);
  } finally {
    await rm(sentinel, { force: true });
    if (createdRootDist) {
      await rm(rootDist, { force: true, recursive: true });
    }
  }
});

test("clean-package-dist rejects extra arguments without deleting dist", async () => {
  const packageRoot = packageRoots[0];
  const distDirectory = join(packageRoot, "dist");
  const sentinel = join(distDirectory, "argument-sentinel.txt");

  try {
    await rm(distDirectory, { force: true, recursive: true });
    await mkdir(distDirectory);
    await writeFile(sentinel, "argument\n");

    await expectCleanerFailure(
      packageRoot,
      ["unexpected"],
      /does not accept command-line arguments/,
    );
    assert.equal(await readFile(sentinel, "utf8"), "argument\n");
  } finally {
    await rm(distDirectory, { force: true, recursive: true });
  }
});

test("clean-package-dist unlinks a dist symlink without touching its target", async () => {
  const packageRoot = packageRoots[1];
  const distDirectory = join(packageRoot, "dist");
  const outsideDirectory = await mkdtemp(
    join(tmpdir(), "pg72-clean-dist-outside-"),
  );
  const sentinel = join(outsideDirectory, "outside-sentinel.txt");

  try {
    await rm(distDirectory, { force: true, recursive: true });
    await writeFile(sentinel, "outside\n");
    await symlink(
      outsideDirectory,
      distDirectory,
      process.platform === "win32" ? "junction" : "dir",
    );

    await runCleaner(packageRoot);
    await assertMissing(distDirectory);
    assert.equal(await readFile(sentinel, "utf8"), "outside\n");
  } finally {
    try {
      if ((await lstat(distDirectory)).isSymbolicLink()) {
        await rm(distDirectory, { force: true });
      }
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    await rm(outsideDirectory, { force: true, recursive: true });
  }
});
