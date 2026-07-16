import { readdir, realpath, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

if (process.argv.length !== 2) {
  throw new Error(
    "check-copy-token-prerequisites does not accept command-line arguments",
  );
}

const scriptPath = await realpath(fileURLToPath(import.meta.url));
const repoRoot = dirname(dirname(scriptPath));
const copyRoot = join(repoRoot, "原專案代碼", "copy.pg72.tw");
const requiredFiles = [
  "cloudflare-env.d.ts",
  "lib/session-logout-route.test.ts",
  "lib/sso-token-session.test.ts",
];

try {
  const [migrationFiles] = await Promise.all([
    readdir(join(copyRoot, "migrations")),
    ...requiredFiles.map((relativePath) => stat(join(copyRoot, relativePath))),
  ]);
  if (!migrationFiles.some((fileName) => fileName.endsWith(".sql"))) {
    throw new Error("no SQL migrations found");
  }
} catch {
  throw new Error(
    "Copy token checks require the ignored Copy checkout with migrations/*.sql and its test support files under 原專案代碼/copy.pg72.tw",
  );
}
