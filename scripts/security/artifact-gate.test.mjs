import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { validateArtifactFiles } from "./artifact-gate.mjs";

const basePolicy = {
  entrypoint: "index.js",
  maxEntrypointBytes: 1024,
  maxTotalBytes: 2048,
  allowedFiles: ["README\\.md", "index\\.js", "assets/[A-Za-z0-9_-]+\\.js"],
};

function fixture() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "pgid-artifact-test-"));
  mkdirSync(path.join(directory, "assets"));
  writeFileSync(path.join(directory, "README.md"), "dry-run output");
  writeFileSync(path.join(directory, "index.js"), "export default {};");
  writeFileSync(path.join(directory, "assets", "chunk-a.js"), "export const value = 1;");
  return directory;
}

test("accepts a bounded allowlisted Worker artifact", (context) => {
  const directory = fixture();
  context.after(() => rmSync(directory, { force: true, recursive: true }));
  const result = validateArtifactFiles(directory, basePolicy);
  assert.equal(result.files.length, 3);
});

test("rejects source maps and unexpected files", (context) => {
  const directory = fixture();
  context.after(() => rmSync(directory, { force: true, recursive: true }));
  writeFileSync(path.join(directory, "index.js.map"), "{}");
  assert.throws(() => validateArtifactFiles(directory, basePolicy), /unexpected artifact file/);
});

test("rejects private machine paths and embedded secrets", (context) => {
  const directory = fixture();
  context.after(() => rmSync(directory, { force: true, recursive: true }));
  writeFileSync(path.join(directory, "index.js"), 'const path = "/Users/operator/private";');
  assert.throws(() => validateArtifactFiles(directory, basePolicy), /private machine path/);

  const secret = "F".repeat(40);
  writeFileSync(path.join(directory, "index.js"), `BETTER_AUTH_SECRET=${secret}`);
  assert.throws(
    () => validateArtifactFiles(directory, basePolicy),
    (error) => {
      assert.match(error.message, /redacted secret family \[assigned-secret\]/);
      assert.ok(!error.message.includes(secret));
      return true;
    },
  );
});

test("uses the shared redacted family engine for binary artifact content", (context) => {
  const directory = fixture();
  context.after(() => rmSync(directory, { force: true, recursive: true }));
  const token = ["xoxb", "987654321098765432109876"].join("-");
  writeFileSync(
    path.join(directory, "index.js"),
    Buffer.concat([Buffer.from("binary\0"), Buffer.from(token), Buffer.from("\0tail")]),
  );
  assert.throws(
    () => validateArtifactFiles(directory, basePolicy),
    (error) => {
      assert.match(error.message, /index\.js contains redacted secret family \[slack-token\]/);
      assert.ok(!error.message.includes(token));
      return true;
    },
  );
});
