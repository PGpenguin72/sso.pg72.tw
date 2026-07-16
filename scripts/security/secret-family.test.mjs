import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  enumerateWorkingTreeFiles,
  redactedFindings,
  scanBufferForSecrets,
  scanWorkingTree,
} from "./secret-family.mjs";

function git(root, args) {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
}

function repository(context) {
  const root = mkdtempSync(path.join(os.tmpdir(), "pgid-secret-family-"));
  context.after(() => rmSync(root, { force: true, recursive: true }));
  git(root, ["init", "--quiet"]);
  writeFileSync(
    path.join(root, ".gitignore"),
    [".env*", "ignored/", ".artifacts/", "dist/", "node_modules/", "*.key", ""].join("\n"),
  );
  writeFileSync(path.join(root, "tracked.txt"), "safe tracked content\n");
  git(root, ["add", ".gitignore", "tracked.txt"]);
  return root;
}

function assigned(name, value) {
  return `${name}=${value}\n`;
}

test("enumerates tracked, untracked, and ignored sensitive paths independently of gitignore", (context) => {
  const root = repository(context);
  writeFileSync(path.join(root, "ordinary.txt"), "safe untracked content\n");
  writeFileSync(path.join(root, ".env.local"), "safe ignored placeholder\n");
  mkdirSync(path.join(root, "ignored", "nested"), { recursive: true });
  writeFileSync(path.join(root, "ignored", "nested", ".dev.vars.preview"), "safe placeholder\n");
  mkdirSync(path.join(root, ".artifacts", "nested"), { recursive: true });
  writeFileSync(path.join(root, ".artifacts", "nested", "signing.key"), "safe placeholder\n");
  mkdirSync(path.join(root, ".docker"), { recursive: true });
  writeFileSync(path.join(root, ".docker", "config.json"), "safe placeholder\n");

  const files = enumerateWorkingTreeFiles(root);
  const categories = Object.fromEntries(files.map((file) => [file.path, file.category]));
  assert.equal(categories["tracked.txt"], "tracked");
  assert.equal(categories["ordinary.txt"], "untracked");
  assert.equal(categories[".env.local"], "ignored-sensitive");
  assert.equal(categories["ignored/nested/.dev.vars.preview"], "ignored-sensitive");
  assert.equal(categories[".artifacts/nested/signing.key"], "ignored-sensitive");
  assert.equal(categories[".docker/config.json"], "untracked");
});

test("detects root, nested, untracked, ignored, and NUL-delimited binary secrets", (context) => {
  const root = repository(context);
  const rootValue = ["xoxb", "123456789012345678901234"].join("-");
  const nestedValue = ["123456789", "A".repeat(35)].join(":");
  const ordinaryValue = ["AKIA", "A1B2C3D4E5F6G7H8"].join("");
  const binaryValue = "B".repeat(40);
  writeFileSync(path.join(root, ".env.local"), assigned("SLACK_TOKEN", rootValue));
  mkdirSync(path.join(root, "ignored", "nested"), { recursive: true });
  writeFileSync(
    path.join(root, "ignored", "nested", ".dev.vars.preview"),
    assigned("TELEGRAM_BOT_TOKEN", nestedValue),
  );
  writeFileSync(path.join(root, "ordinary.txt"), ordinaryValue);
  writeFileSync(
    path.join(root, "binary.dat"),
    Buffer.concat([
      Buffer.from("header\0AWS_SECRET_ACCESS_KEY\0=\0", "utf8"),
      Buffer.from(binaryValue, "utf8"),
      Buffer.from("\0footer", "utf8"),
    ]),
  );

  const findings = scanWorkingTree(root);
  assert.ok(findings.some(({ path: name, rule }) => name === ".env.local" && rule === "slack-token"));
  assert.ok(
    findings.some(
      ({ path: name, rule }) =>
        name === "ignored/nested/.dev.vars.preview" && rule === "telegram-bot-token",
    ),
  );
  assert.ok(findings.some(({ path: name, rule }) => name === "ordinary.txt" && rule === "aws-access-key-id"));
  assert.ok(findings.some(({ path: name, rule }) => name === "binary.dat" && rule === "assigned-secret"));

  const output = redactedFindings(findings);
  for (const secret of [rootValue, nestedValue, ordinaryValue, binaryValue]) {
    assert.ok(!output.includes(secret), "redacted output included secret material");
  }
});

test("fails closed on oversized files and symlinks without reading or logging content", (context) => {
  const root = repository(context);
  const secretValue = "C".repeat(80);
  writeFileSync(path.join(root, "large.txt"), assigned("SERVICE_PASSWORD", secretValue));
  const outside = path.join(os.tmpdir(), `pgid-secret-outside-${process.pid}.txt`);
  writeFileSync(outside, secretValue);
  context.after(() => rmSync(outside, { force: true }));
  symlinkSync(outside, path.join(root, "linked.txt"));

  const findings = scanWorkingTree(root, { maxFileBytes: 32 });
  assert.ok(findings.some(({ path: name, rule }) => name === "large.txt" && rule === "file-too-large-to-scan"));
  assert.ok(findings.some(({ path: name, rule }) => name === "linked.txt" && rule === "symbolic-link"));
  assert.ok(!redactedFindings(findings).includes(secretValue));
});

test("shared family engine covers artifact token and key families including binary strings", () => {
  const fixtures = new Map([
    ["aws-access-key-id", Buffer.from(["AKIA", "Z9Y8X7W6V5U4T3S2"].join(""))],
    ["slack-token", Buffer.from(["xoxb", "123456789012345678901234"].join("-"))],
    ["telegram-bot-token", Buffer.from(["123456789", "D".repeat(35)].join(":"))],
    ["private-key", Buffer.from(["-----BEGIN ", "PRIVATE KEY-----"].join(""))],
    [
      "assigned-secret",
      Buffer.from(`prefix\0GENERIC_API_KEY\0=\0${"E".repeat(40)}\0suffix`, "utf8"),
    ],
  ]);
  for (const [expected, bytes] of fixtures) {
    assert.ok(scanBufferForSecrets(bytes).includes(expected), `missing ${expected}`);
  }
});
