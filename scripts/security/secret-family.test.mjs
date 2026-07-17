import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  classifyDiagnosticPath,
  diagnosticPath,
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

test("allows only exact audited path, key, and complete value triples", () => {
  const fixtures = [
    [
      "apps/sso/.dev.vars.example",
      "BETTER_AUTH_SECRET",
      "generate-with-openssl-rand-base64-32",
    ],
    [
      "apps/sso/.dev.vars.example",
      "GOOGLE_CLIENT_SECRET",
      "replace-with-google-oauth-client-secret",
    ],
    [
      "apps/sso/.dev.vars.example",
      "TURNSTILE_SECRET_KEY",
      "replace-with-turnstile-secret-key",
    ],
    [
      "apps/sso/vitest.config.ts",
      "BETTER_AUTH_SECRET",
      "test-only-better-auth-secret-0000000000000000",
    ],
    ["apps/sso/vitest.config.ts", "GOOGLE_CLIENT_SECRET", "test-only-google-secret"],
    [
      "apps/sso/vitest.config.ts",
      "TURNSTILE_SECRET_KEY",
      "test-only-turnstile-secret",
    ],
    [
      "apps/sso/vitest.config.ts",
      "TELEGRAM_BOT_TOKEN",
      "123456:AAvitest-telegram-bot-token",
    ],
    [
      "apps/sso/test/registration.spec.ts",
      "GITHUB_CLIENT_SECRET",
      "test-github-client-secret",
    ],
    [
      "apps/sso/worker/auth.cli.ts",
      "BETTER_AUTH_SECRET",
      "cli-only-placeholder-secret-at-least-32-characters",
    ],
    ["apps/sso/worker/auth.cli.ts", "GOOGLE_CLIENT_SECRET", "cli-placeholder"],
    ["wiki/developers/register-client.md", "OIDC_CLIENT_SECRET", "pg72_cs_xxxxxxxx"],
    ["artifact:worker/index.js", "INVALID_PASSWORD", "Invalid password"],
    [
      "artifact:worker/index.js",
      "INVALID_EMAIL_OR_PASSWORD",
      "Invalid email or password",
    ],
    ["artifact:worker/index.js", "INVALID_TOKEN", "Invalid token"],
    ["artifact:worker/index.js", "ID_TOKEN_NOT_SUPPORTED", "id_token not supported"],
    [
      "artifact:worker/index.js",
      "USER_ALREADY_HAS_PASSWORD",
      "User already has a password. Provide that to delete the account.",
    ],
  ];

  for (const [relativePath, key, value] of fixtures) {
    const bytes = Buffer.from(`${key}="${value}"`);
    assert.ok(!scanBufferForSecrets(bytes, { relativePath }).includes("assigned-secret"));
    assert.ok(
      scanBufferForSecrets(bytes, { relativePath: `other/${path.basename(relativePath)}` }).includes(
        "assigned-secret",
      ),
      relativePath,
    );
    assert.ok(
      scanBufferForSecrets(bytes, { relativePath: relativePath.replaceAll("/", "\\") }).includes(
        "assigned-secret",
      ),
      relativePath,
    );
    assert.ok(
      scanBufferForSecrets(Buffer.from(`${key}="${value}-appended"`), { relativePath }).includes(
        "assigned-secret",
      ),
      relativePath,
    );
    assert.ok(
      scanBufferForSecrets(Buffer.from(`OTHER_SECRET="${value}"`), { relativePath }).includes(
        "assigned-secret",
      ),
      relativePath,
    );
  }
});

test("normalizes declarations and quoted or unquoted secret keys before classification", () => {
  for (const assignment of [
    'clientSecret: "camel case secret material 123456"',
    'const SERVICE_SECRET = "const declaration material 123456"',
    "let apiKey = 'let declaration material 123456'",
    "var accessToken = `var declaration material 123456`",
    'export const privateKey = "export declaration material 123456"',
    '"client-secret": "quoted kebab material 123456"',
    "'client.secret': 'quoted dot material 123456'",
    "`client@secret`: `quoted nonalnum material 123456`",
    "const clientSecret = unquoted passphrase with spaces : and = punctuation 123456",
  ]) {
    assert.ok(
      scanBufferForSecrets(Buffer.from(assignment)).includes("assigned-secret"),
      assignment,
    );
  }
  assert.ok(
    scanBufferForSecrets(Buffer.from(`const serviceSecret = ${"F".repeat(40)}`), {
      relativePath: "artifact:worker/extra.js",
    }).includes("assigned-secret"),
  );
});

test("excludes nonliteral source expressions rather than treating them as embedded bytes", () => {
  for (const assignment of [
    "const clientSecret = env.CLIENT_SECRET",
    "privateKey: CryptoKey;",
    "hasSecret: row.hasSecret === 1,",
    "const accessToken = `pg72_at_${runtimeSuffix}`",
    "const tokenResponse = await oauth.authorizationCodeGrantRequest(",
    "sessionTokenMaxAge: dontRememberMe ? void 0 : ctx.context.sessionConfig.expiresIn",
    "sendResetPassword: !!options.emailAndPassword?.sendResetPassword",
  ]) {
    assert.ok(
      !scanBufferForSecrets(Buffer.from(assignment), { relativePath: "example.ts" }).includes(
        "assigned-secret",
      ),
      assignment,
    );
  }
});

test("applies allowances to normalized keys only after detecting the secret family", () => {
  const relativePath = "apps/sso/.dev.vars.example";
  const value = "generate-with-openssl-rand-base64-32";
  const camelAssignment = Buffer.from(`betterAuthSecret="${value}"`);
  assert.ok(
    !scanBufferForSecrets(camelAssignment, { relativePath }).includes("assigned-secret"),
  );
  assert.ok(
    scanBufferForSecrets(camelAssignment, { relativePath: `other/${relativePath}` }).includes(
      "assigned-secret",
    ),
  );

  const directToken = ["xoxb", "314159265358979323846264"].join("-");
  const findings = scanBufferForSecrets(
    Buffer.from(`betterAuthSecret="${directToken}"`),
    { relativePath },
  );
  assert.ok(findings.includes("slack-token"));
  assert.ok(findings.includes("assigned-secret"));
});

test("allows exact generated enums but rejects wrong paths, keys, and values", () => {
  const exactEnums = [
    ["INVALID_PASSWORD", "Invalid password"],
    ["INVALID_EMAIL_OR_PASSWORD", "Invalid email or password"],
    ["INVALID_TOKEN", "Invalid token"],
    ["TOKEN_EXPIRED", "Token expired"],
    ["ID_TOKEN_NOT_SUPPORTED", "id_token not supported"],
    ["PASSWORD_TOO_SHORT", "Password too short"],
    ["PASSWORD_TOO_LONG", "Password too long"],
    ["CREDENTIAL_ACCOUNT_NOT_FOUND", "Credential account not found"],
    [
      "USER_ALREADY_HAS_PASSWORD",
      "User already has a password. Provide that to delete the account.",
    ],
    ["PASSWORD_ALREADY_SET", "User already has a password set"],
    ["DEFAULT_SECRET", "better-auth-secret-12345678901234567890"],
    ["PEM_CONVERTER_PRIVATE_KEY_TAG", "PRIVATE KEY"],
    ["CHALLENGE_PASSWORD_ATTRIBUTE_NAME", "Challenge Password"],
    ["CLIENT_SECRET_PREFIX", "pg72_cs_"],
    ["OPAQUE_ACCESS_TOKEN", "pg72_at_"],
    ["REFRESH_TOKEN", "pg72_rt_"],
  ];
  const source = Buffer.from(
    exactEnums.map(([key, value]) => `${key}: "${value}",`).join("\n"),
  );
  assert.ok(
    !scanBufferForSecrets(source, { relativePath: "artifact:worker/index.js" }).includes(
      "assigned-secret",
    ),
  );
  assert.ok(
    scanBufferForSecrets(source, { relativePath: "artifact:static/index.js" }).includes(
      "assigned-secret",
    ),
  );
  assert.ok(
    !scanBufferForSecrets(Buffer.from('invalidPassword: "Invalid password",'), {
      relativePath: "artifact:worker/index.js",
    }).includes("assigned-secret"),
  );
  assert.ok(
    scanBufferForSecrets(Buffer.from('INVALID_PASSWORD: "Invalid password changed",'), {
      relativePath: "artifact:worker/index.js",
    }).includes("assigned-secret"),
  );
});

test("placeholder-like substrings never waive an unaudited assigned value", () => {
  for (const value of [
    "real-test-only-credential-material-123456",
    "production-example-secret-material-123456",
    "placeholder-inside-real-secret-material-123456",
    "replace-this-marker-plus-real-material-123456",
    "synthetic-word-does-not-waive-material-123456",
    "dummy-marker-does-not-waive-material-123456",
    "fake-marker-does-not-waive-material-123456",
    "fixture-marker-does-not-waive-material-123456",
    "not-a-real-marker-does-not-waive-material-123456",
    "xxxxxxxx-followed-by-real-material-123456",
    "your-secret-prefix-followed-by-material-123456",
    "${UNTRUSTED_SECRET_EXPRESSION_WITH_PADDING}",
  ]) {
    assert.ok(
      scanBufferForSecrets(Buffer.from(`SERVICE_SECRET="${value}"`)).includes("assigned-secret"),
      value,
    );
  }
});

test("direct token and key families are never waived by marker words or fixture paths", () => {
  const telegramPayload = "test_example_placeholder_".padEnd(35, "A");
  for (const [expected, value] of [
    ["aws-access-key-id", ["AKIA", "TESTEXAMPLE12345"].join("")],
    ["telegram-bot-token", `123456789:${telegramPayload}`],
    ["private-key", ["-----BEGIN TEST ", "PRIVATE KEY-----"].join("")],
  ]) {
    const findings = scanBufferForSecrets(Buffer.from(value), {
      relativePath: "apps/sso/.dev.vars.example",
    });
    assert.ok(findings.includes(expected), expected);
  }
});

test("parses quote variants, whitespace, passphrases, punctuation, and multiline values", () => {
  for (const assignment of [
    "SERVICE_SECRET = 'correct horse battery staple 1234'",
    '\"SERVICE_TOKEN\" : \"value with spaces:and=punctuation 1234\"',
    '\"clientSecret\" : \"quoted camel case example credential 1234\"',
    "'SERVICE_API_KEY' = `backtick value with : colon and = equals 1234`",
    "`SERVICE_PASSWORD` : 'single quoted passphrase with spaces 1234'",
    "SERVICE_CREDENTIAL = unquoted passphrase with spaces : and = punctuation 1234",
    "SERVICE_PRIVATE_KEY = `first bounded line 1234\nsecond line: value=5678`",
    "SERVICE_PASSWORD='escaped \\' quote remains bounded secret 1234'",
  ]) {
    assert.ok(
      scanBufferForSecrets(Buffer.from(assignment)).includes("assigned-secret"),
      assignment,
    );
  }

  const oversized = `SERVICE_SECRET="${"Z".repeat(4097)}"`;
  assert.ok(scanBufferForSecrets(Buffer.from(oversized)).includes("assigned-secret"));

  for (const metadata of [
    'tokenEndpoint: "https://issuer.example/token"',
    'tokenEndpointAuthMethod: "client_secret_post"',
    'token_type_hint: "access_token"',
  ]) {
    assert.ok(!scanBufferForSecrets(Buffer.from(metadata)).includes("assigned-secret"), metadata);
  }
});

test("hashes secret-family, sensitive, outside, and terminal-unsafe diagnostic paths", () => {
  const token = ["xoxb", "135791357913579135791357"].join("-");
  const unsafePaths = [
    `.env.${process.pid}`,
    "nested/credentials.json",
    `assets/${token}.js`,
    `SERVICE_SECRET=${"Q".repeat(32)}/file.txt`,
    `assets/SERVICE_SECRET=${"W".repeat(32)}.txt`,
    `../outside/${token}.txt`,
    "/absolute/path.txt",
    "C:\\Users\\operator\\credential.txt",
    "assets/line\nbreak.js",
    "assets/escape\u001bsequence.js",
    "assets/non-ascii-credential-\u00e9.js",
  ];
  for (const unsafePath of unsafePaths) {
    const classified = classifyDiagnosticPath(unsafePath);
    assert.equal(classified.unsafe, true, unsafePath);
    assert.match(classified.display, /^\[redacted-path:sha256:[a-f0-9]{16}]$/);
    assert.ok(!classified.display.includes(unsafePath));
    assert.equal(diagnosticPath(unsafePath), classified.display);
  }

  assert.deepEqual(classifyDiagnosticPath("assets/../assets/chunk.js"), {
    display: "assets/chunk.js",
    normalized: "assets/chunk.js",
    unsafe: false,
  });
});

test("redacts hostile symlink, oversized, sensitive, control, and outside finding paths", (context) => {
  const root = repository(context);
  const token = ["xoxb", "246802468024680246802468"].join("-");
  const oversizedName = `${token}.txt`;
  writeFileSync(path.join(root, oversizedName), "X".repeat(64));

  const outside = path.join(os.tmpdir(), `pgid-secret-path-outside-${process.pid}.txt`);
  writeFileSync(outside, "safe outside content");
  context.after(() => rmSync(outside, { force: true }));
  const symlinkName = `linked-${token}.txt`;
  symlinkSync(outside, path.join(root, symlinkName));

  const sensitiveName = `.env.${process.pid}`;
  writeFileSync(path.join(root, sensitiveName), "Y".repeat(64));
  const controlName = "control\nname.txt";
  writeFileSync(path.join(root, controlName), assigned("SERVICE_SECRET", "R".repeat(32)));

  const findings = scanWorkingTree(root, { maxFileBytes: 32 });
  const output = `${redactedFindings(findings)}\n${redactedFindings([
    { path: `../outside/${token}.txt`, rule: "file-read-error" },
  ])}`;
  for (const unsafePath of [oversizedName, symlinkName, sensitiveName, controlName, token]) {
    assert.ok(!output.includes(unsafePath), unsafePath);
  }
  assert.match(output, /\[redacted-path:sha256:[a-f0-9]{16}]/);
  assert.ok(findings.some(({ rule }) => rule === "file-too-large-to-scan"));
  assert.ok(findings.some(({ rule }) => rule === "symbolic-link"));
});
