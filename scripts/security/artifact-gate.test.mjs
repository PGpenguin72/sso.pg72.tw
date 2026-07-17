import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  validateArtifactFiles,
  validateProductionWorkerArtifactFiles,
  validateProductionWorkerEntrypointIdentity,
} from "./artifact-gate.mjs";
import { scanBufferForSecrets } from "./secret-family.mjs";

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

function reviewedGeneratedFallbacks(body) {
  const value = ["better", "auth", "secret", "12345678901234567890"].join("-");
  const literal = JSON.stringify(value);
  return [
    body,
    `var DEFAULT_SECRET = ${literal};`,
    `function buildSecretConfig(legacySecret) { return { legacySecret: legacySecret && legacySecret !== ${literal} ? legacySecret : void 0 }; }`,
    `async function createAuthContext(legacySecret) { let secret; secret = legacySecret || ${literal}; }`,
  ].join("\n");
}

function fallbackBehavioralDecoys(count) {
  const overrides = [
    "DEFAULT_SECRET = void 0;",
    "function buildSecretConfig(legacySecret) { return { legacySecret: void 0 }; }",
    "async function createAuthContext(legacySecret) { let secret; secret = legacySecret; }",
  ];
  return `${reviewedGeneratedFallbacks("")}\n${overrides.slice(0, count).join("\n")}`;
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
  writeFileSync(path.join(directory, "index.js"), `const BETTER_AUTH_SECRET="${secret}";`);
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

test("allows only exact reviewed Worker error-enum assignments", (context) => {
  const directory = fixture();
  context.after(() => rmSync(directory, { force: true, recursive: true }));
  writeFileSync(
    path.join(directory, "index.js"),
    reviewedGeneratedFallbacks('const errors = { INVALID_PASSWORD: "Invalid password" };'),
  );
  assert.doesNotThrow(() =>
    validateArtifactFiles(directory, basePolicy, { scanRoot: "artifact:worker" }),
  );
  assert.throws(
    () => validateArtifactFiles(directory, basePolicy),
    /redacted secret family \[assigned-secret]/,
  );

  writeFileSync(
    path.join(directory, "index.js"),
    reviewedGeneratedFallbacks(
      'const errors = { INVALID_PASSWORD: "Invalid password with appended material" };',
    ),
  );
  assert.throws(
    () => validateArtifactFiles(directory, basePolicy, { scanRoot: "artifact:worker" }),
    /redacted secret family \[assigned-secret]/,
  );
});

test("rejects wrong production entry digests before the structural artifact scanner", (context) => {
  const directory = fixture();
  context.after(() => rmSync(directory, { force: true, recursive: true }));
  assert.throws(
    () => validateProductionWorkerEntrypointIdentity(Buffer.from("export default {};")),
    /entrypoint identity/,
  );
  assert.throws(
    () => validateProductionWorkerArtifactFiles(directory, basePolicy),
    /entrypoint identity/,
  );
});

test("whole-entry identity rejects one, two, and three reviewed-context decoys", () => {
  for (const count of [1, 2, 3]) {
    const source = Buffer.from(fallbackBehavioralDecoys(count));
    assert.deepEqual(
      scanBufferForSecrets(source, {
        enforceGeneratedLiteralContract: true,
        relativePath: "artifact:worker/index.js",
      }),
      [],
      `${count} decoy override(s) unexpectedly failed the structural control`,
    );
    assert.throws(
      () => validateProductionWorkerEntrypointIdentity(source),
      /entrypoint identity/,
      `${count} decoy override(s) bypassed the whole-entry identity`,
    );
  }
});

test("hashes sensitive, secret-bearing, control-character, and outside artifact paths", (context) => {
  const token = ["xoxb", "112233445566778899001122"].join("-");
  for (const relative of [
    `.env.${process.pid}`,
    `assets/${token}.js`,
    "assets/control\nname.js",
  ]) {
    const directory = fixture();
    context.after(() => rmSync(directory, { force: true, recursive: true }));
    writeFileSync(path.join(directory, relative), "safe content");
    assert.throws(
      () => validateArtifactFiles(directory, basePolicy),
      (error) => {
        assert.match(error.message, /\[redacted-path:sha256:[a-f0-9]{16}]/);
        assert.ok(!error.message.includes(relative));
        assert.ok(!error.message.includes(token));
        return true;
      },
    );
  }

  const directory = fixture();
  context.after(() => rmSync(directory, { force: true, recursive: true }));
  const outsidePolicy = { ...basePolicy, entrypoint: `../outside/${token}.js` };
  assert.throws(
    () => validateArtifactFiles(directory, outsidePolicy),
    (error) => {
      assert.match(error.message, /missing \[redacted-path:sha256:[a-f0-9]{16}]/);
      assert.ok(!error.message.includes(token));
      return true;
    },
  );
});

test("does not expose a secret-bearing symlink path or target", (context) => {
  const directory = fixture();
  context.after(() => rmSync(directory, { force: true, recursive: true }));
  const token = ["xoxb", "998877665544332211009988"].join("-");
  const outside = path.join(os.tmpdir(), `artifact-target-${token}.js`);
  writeFileSync(outside, "outside content");
  context.after(() => rmSync(outside, { force: true }));
  const relative = `assets/${token}.js`;
  symlinkSync(outside, path.join(directory, relative));

  assert.throws(
    () => validateArtifactFiles(directory, basePolicy),
    (error) => {
      assert.match(error.message, /unsafe artifact path: \[redacted-path:sha256:/);
      assert.ok(!error.message.includes(token));
      assert.ok(!error.message.includes(outside));
      return true;
    },
  );
});

test("keeps secret-bearing diagnostic paths out of combined stdout and stderr", (context) => {
  const directory = fixture();
  context.after(() => rmSync(directory, { force: true, recursive: true }));
  const token = ["xoxb", "102938475610293847561029"].join("-");
  writeFileSync(path.join(directory, "assets", `${token}.js`), "safe content");
  const moduleUrl = new URL("./artifact-gate.mjs", import.meta.url).href;
  const program = `
    import { validateArtifactFiles } from ${JSON.stringify(moduleUrl)};
    const policy = ${JSON.stringify(basePolicy)};
    try {
      validateArtifactFiles(process.env.ARTIFACT_TEST_DIRECTORY, policy);
    } catch (error) {
      console.log(error.message);
      console.error(error.message);
      process.exitCode = 1;
    }
  `;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", program], {
    encoding: "utf8",
    env: { ...process.env, ARTIFACT_TEST_DIRECTORY: directory },
  });
  assert.equal(result.status, 1);
  const combined = `${result.stdout}${result.stderr}`;
  assert.match(combined, /\[redacted-path:sha256:[a-f0-9]{16}]/);
  assert.ok(!combined.includes(token));
});

test("does not expose an unreadable or missing artifact directory argument", () => {
  const token = ["xoxb", "564738291056473829105647"].join("-");
  const missing = path.join(os.tmpdir(), `missing-${token}`, "nested");
  assert.throws(
    () => validateArtifactFiles(missing, basePolicy),
    (error) => {
      assert.match(error.message, /unable to read artifact directory: \./);
      assert.ok(!error.message.includes(token));
      assert.ok(!error.message.includes(missing));
      return true;
    },
  );
});
