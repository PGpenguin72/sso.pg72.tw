import { lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

import { analyzeTypeScriptStaticValues } from "./typescript-static-values.mjs";

export const DEFAULT_MAX_SCAN_BYTES = 8 * 1024 * 1024;

const fullyExcludedDirectories = new Set([".git"]);

const tokenRules = [
  { name: "aws-access-key-id", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { name: "github-token", pattern: /\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b/ },
  { name: "google-api-key", pattern: /\bAIza[0-9A-Za-z_-]{30,}\b/ },
  { name: "slack-token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/ },
  { name: "telegram-bot-token", pattern: /\b[0-9]{8,12}:[A-Za-z0-9_-]{35}\b/ },
  { name: "private-key", pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ },
];

const MIN_ASSIGNMENT_VALUE_CHARS = 8;
const MAX_ASSIGNMENT_VALUE_CHARS = 4096;

// These reviewed source fixtures and generated error enums are not substring
// heuristics. An allowance applies only when raw path, normalized key, and
// complete value match.
function assignmentAllowances(entries) {
  const allowances = new Map();
  for (const [normalizedKey, value] of entries) {
    if (!/^[A-Z0-9]+(?:_[A-Z0-9]+)*$/.test(normalizedKey)) {
      throw new Error("assignment allowance keys must already be normalized");
    }
    const values = allowances.get(normalizedKey) ?? new Set();
    values.add(value);
    allowances.set(normalizedKey, values);
  }
  return allowances;
}

const auditedAssignmentAllowances = new Map([
  [
    "apps/sso/.dev.vars.example",
    assignmentAllowances([
      ["BETTER_AUTH_SECRET", "generate-with-openssl-rand-base64-32"],
      ["GOOGLE_CLIENT_SECRET", "replace-with-google-oauth-client-secret"],
      ["TURNSTILE_SECRET_KEY", "replace-with-turnstile-secret-key"],
    ]),
  ],
  [
    "apps/sso/vitest.config.ts",
    assignmentAllowances([
      ["BETTER_AUTH_SECRET", "test-only-better-auth-secret-0000000000000000"],
      ["GOOGLE_CLIENT_SECRET", "test-only-google-secret"],
      ["TURNSTILE_SECRET_KEY", "test-only-turnstile-secret"],
      ["TELEGRAM_BOT_TOKEN", "123456:AAvitest-telegram-bot-token"],
    ]),
  ],
  [
    "apps/sso/test/registration.spec.ts",
    assignmentAllowances([
      ["GITHUB_CLIENT_SECRET", "test-github-client-secret"],
      ["TURNSTILE_TOKEN", "test-route-token"],
      ["TURNSTILE_TOKEN", "not-used"],
      ["ACCESS_TOKEN", "test-google-access-token"],
      ["ACCESS_TOKEN", "test-github-access-token"],
    ]),
  ],
  [
    "apps/sso/worker/auth.cli.ts",
    assignmentAllowances([
      ["BETTER_AUTH_SECRET", "cli-only-placeholder-secret-at-least-32-characters"],
      ["GOOGLE_CLIENT_SECRET", "cli-placeholder"],
    ]),
  ],
  [
    "apps/sso/test/introspection.spec.ts",
    assignmentAllowances([
      ["TOKEN", "pg72_at_sensitive-token"],
      ["TOKEN", "pg72_at_unknown"],
    ]),
  ],
  [
    "apps/sso/test/sid.spec.ts",
    assignmentAllowances([["CLIENT_SECRET_PREFIX", "pg72_cs_"]]),
  ],
  [
    "apps/sso/test/telegram.spec.ts",
    assignmentAllowances([["BOT_TOKEN", "123456:AAvitest-telegram-bot-token"]]),
  ],
  [
    "apps/sso/worker/auth.ts",
    assignmentAllowances([
      ["OPAQUE_ACCESS_TOKEN", "pg72_at_"],
      ["REFRESH_TOKEN", "pg72_rt_"],
    ]),
  ],
  [
    "apps/sso/worker/config.ts",
    assignmentAllowances([["CLIENT_SECRET_PREFIX", "pg72_cs_"]]),
  ],
  [
    "apps/test-rp/test/worker.spec.ts",
    assignmentAllowances([
      ["ACCESS_TOKEN", "test-access-token"],
      ["TOKEN", "legacy-null-sid-session-token"],
    ]),
  ],
  [
    "wiki/developers/register-client.md",
    assignmentAllowances([["OIDC_CLIENT_SECRET", "pg72_cs_xxxxxxxx"]]),
  ],
  [
    "artifact:worker/index.js",
    assignmentAllowances([
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
      ["PEM_CONVERTER_PRIVATE_KEY_TAG", "PRIVATE KEY"],
      ["PRIVATE_KEY_TAG", "PRIVATE KEY"],
      ["CHALLENGE_PASSWORD_ATTRIBUTE_NAME", "Challenge Password"],
      ["CLIENT_SECRET_PREFIX", "pg72_cs_"],
      ["OPAQUE_ACCESS_TOKEN", "pg72_at_"],
      ["REFRESH_TOKEN", "pg72_rt_"],
    ]),
  ],
]);

const auditedAssignmentDigestAllowances = new Map([
  [
    "apps/sso/src/App.tsx",
    new Map([
      [
        "REFRESH_TOKEN_REQUIRES_OFFLINE_ACCESS",
        new Set(["bbf58f13f3573e210bba2822828db86d1b334f38cb40c7892246fcc83e2b3726"]),
      ],
    ]),
  ],
  [
    "apps/sso/test/worker.spec.ts",
    new Map([
      [
        "CLIENT_SECRET_POST_MIGRATION",
        new Set(["0672e4773de59a6c943466916c939e0bab895a8735668a1d47496439f36e69e3"]),
      ],
    ]),
  ],
]);

const auditedStaticLiteralAllowances = new Map([
  [
    "artifact:worker/index.js",
    new Map([
      [
        "high-entropy-string",
        new Set([
          "775ad11d37eebfe985acd54acdaa5d2c40181421389044b87d29d62182a43e6c",
          "7543b37fa53fde2c84f07fd39f368555966aa1c0eb2f2fd26b294d79966e290e",
        ]),
      ],
    ]),
  ],
  [
    "apps/sso/test/avatar.spec.ts",
    new Map([
      [
        "high-entropy-string",
        new Set(["c2940c2c0aaac7becda21c33fe8685c27f4ee3e94c4af302cd0d44592bd9c3e6"]),
      ],
    ]),
  ],
]);

function normalizeAssignmentKey(value) {
  return value
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toUpperCase();
}

function isSecretAssignmentKey(normalizedKey) {
  const tokens = normalizedKey.split("_").filter(Boolean);
  const tokenSet = new Set(tokens);
  if (tokenSet.has("CREDENTIAL") && tokenSet.has("DEVICE") && tokenSet.has("TYPE")) {
    return false;
  }
  if (
    tokens.some((token) =>
      ["SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "CREDENTIALS"].includes(token),
    ) ||
    (tokenSet.has("API") && tokenSet.has("KEY")) ||
    (tokenSet.has("PRIVATE") && tokenSet.has("KEY"))
  ) {
    return true;
  }
  if (!tokenSet.has("TOKEN")) return false;
  if (tokenSet.has("ENDPOINT")) return false;
  if (tokenSet.has("TYPE") && tokenSet.has("HINT")) return false;
  return true;
}

function isAuditedFixture(relativePath, normalizedKey, value) {
  return (
    typeof relativePath === "string" &&
    (auditedAssignmentAllowances.get(relativePath)?.get(normalizedKey)?.has(value) === true ||
      auditedAssignmentDigestAllowances
        .get(relativePath)
        ?.get(normalizedKey)
        ?.has(sha256(value)) === true)
  );
}

const generatedSensitiveLiteralContract = Object.freeze({
  path: "artifact:worker/index.js",
  category: "better-auth-default-secret",
  digest: "2988a24c0bcc440e2c600c28394590bf7990f260cbf23503e03ee00092086e1f",
  form: "string-literal",
  contexts: Object.freeze([
    "variable:DEFAULT_SECRET:initializer>VariableDeclarationList>FirstStatement",
    "binary:ExclamationEqualsEqualsToken:right:legacySecret>binary:AmpersandAmpersandToken:right:legacySecret>conditional:condition>property:legacySecret:initializer",
    "binary:BarBarToken:right:legacySecret>binary:FirstAssignment:right:secret>statement:expression>Block",
  ]),
});

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isJavaScriptPath(relativePath) {
  return /\.(?:[cm]?[jt]sx?)$/i.test(relativePath);
}

function isLikelyDecodedText(value) {
  if (!value || value.includes("\u0000")) return false;
  let printable = 0;
  let considered = 0;
  for (const character of value.slice(0, 64 * 1024)) {
    considered += 1;
    const code = character.codePointAt(0);
    if (character === "\t" || character === "\n" || character === "\r" || (code >= 32 && code <= 126)) {
      printable += 1;
    }
  }
  return considered > 0 && printable / considered >= 0.7;
}

function decodedRepresentations(input) {
  const bytes = input.subarray(0, DEFAULT_MAX_SCAN_BYTES);
  const values = new Map();
  function add(kind, value, sourceCandidate = false) {
    const text = value.replace(/^\uFEFF/, "");
    if (!text || values.has(text)) return;
    values.set(text, { kind, sourceCandidate, text });
  }

  const utf8 = bytes.toString("utf8");
  add("utf8", utf8, !utf8.includes("\uFFFD") && !utf8.includes("\u0000"));
  for (const [kind, encoding] of [
    ["utf16le", "utf-16le"],
    ["utf16be", "utf-16be"],
  ]) {
    for (const offset of [0, 1]) {
      if (bytes.length - offset < 4) continue;
      const value = new TextDecoder(encoding).decode(bytes.subarray(offset));
      if (isLikelyDecodedText(value)) add(`${kind}:${offset}`, value, true);
    }
  }

  const printableRuns = [];
  let current = "";
  for (const byte of bytes) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= 4) printableRuns.push(current);
      current = "";
    }
  }
  if (current.length >= 4) printableRuns.push(current);
  add("printable-runs", printableRuns.join("\n"));
  add("nul-collapsed", bytes.toString("latin1").replaceAll("\u0000", ""));
  return [...values.values()];
}

function readQuoted(value, offset) {
  const quote = value[offset];
  let result = "";
  for (let index = offset + 1; index < value.length; index += 1) {
    const character = value[index];
    if (character === "\\" && index + 1 < value.length) {
      result += character + value[index + 1];
      index += 1;
      continue;
    }
    if (character === quote) return { end: index + 1, value: result };
    result += character;
    if (result.length > MAX_ASSIGNMENT_VALUE_CHARS) return { overflow: true };
  }
  return null;
}

function horizontalSpace(value, offset) {
  let index = offset;
  while (value[index] === " " || value[index] === "\t") index += 1;
  return index;
}

function wordAt(value, offset, word) {
  if (!value.startsWith(word, offset)) return false;
  const next = value[offset + word.length];
  return next === undefined || next === " " || next === "\t";
}

function lineAssignmentHeader(line) {
  let offset = horizontalSpace(line, 0);
  if (wordAt(line, offset, "export")) {
    offset = horizontalSpace(line, offset + "export".length);
  }
  for (const declaration of ["const", "let", "var"]) {
    if (wordAt(line, offset, declaration)) {
      offset = horizontalSpace(line, offset + declaration.length);
      break;
    }
  }

  let key;
  if (line[offset] === '"' || line[offset] === "'" || line[offset] === "`") {
    const quoted = readQuoted(line, offset);
    if (!quoted || quoted.overflow || quoted.value.length > 128) return null;
    key = quoted.value.replace(/\\(.)/g, "$1");
    offset = quoted.end;
  } else {
    const start = offset;
    if (!/[A-Za-z_$]/.test(line[offset] ?? "")) return null;
    offset += 1;
    while (offset - start <= 128 && /[A-Za-z0-9_$./@-]/.test(line[offset] ?? "")) {
      offset += 1;
    }
    key = line.slice(start, offset);
  }
  offset = horizontalSpace(line, offset);
  if (line[offset] !== "=" && line[offset] !== ":") return null;
  return { key, valueOffset: horizontalSpace(line, offset + 1) };
}

function lineAssignments(content) {
  const results = [];
  let lineStart = 0;
  while (lineStart <= content.length) {
    const newline = content.indexOf("\n", lineStart);
    const lineEnd = newline === -1 ? content.length : newline;
    const line = content.slice(lineStart, lineEnd).replace(/\r$/, "");
    const header = lineAssignmentHeader(line);
    if (header) {
      const absoluteValueOffset = lineStart + header.valueOffset;
      const first = content[absoluteValueOffset];
      if (first === '"' || first === "'" || first === "`") {
        const quoted = readQuoted(content, absoluteValueOffset);
        results.push({
          key: header.key,
          overflow: !quoted || quoted.overflow === true,
          quoted: true,
          value: quoted && !quoted.overflow ? quoted.value : "",
        });
      } else {
        const value = line
          .slice(header.valueOffset)
          .replace(/[\t ]+(?:#|\/\/).*$/, "")
          .replace(/[\t ]*[,;][\t ]*$/, "")
          .trim();
        results.push({
          key: header.key,
          overflow: value.length > MAX_ASSIGNMENT_VALUE_CHARS,
          quoted: false,
          value,
        });
      }
    }
    if (newline === -1) break;
    lineStart = newline + 1;
  }
  return results;
}

function isNonliteralLineAssignment(relativePath, assignment) {
  if (assignment.quoted || !/\.(?:md|patch|sql)$/i.test(relativePath)) return false;
  const value = assignment.value;
  return (
    /^(?:await|new|void)\b/.test(value) ||
    /\$\(|\$\{|=>/.test(value) ||
    /^[A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*)+/.test(value) ||
    /^(?:true|false|null|undefined|[+-]?\d)/.test(value) ||
    /^[{[(]/.test(value) ||
    /(?:===?|!==?|&&|\|\||\?\?|\binstanceof\b)/.test(value)
  );
}

function shannonEntropy(value) {
  const frequencies = new Map();
  for (const character of value) {
    frequencies.set(character, (frequencies.get(character) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function hasHighEntropyFamily(value) {
  const withoutPublicCertificates = value.replace(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
    "",
  );
  for (const match of withoutPublicCertificates.matchAll(/[A-Za-z0-9+/_=-]{40,}/g)) {
    const candidate = match[0];
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[+/_=-]/].filter((pattern) =>
      pattern.test(candidate),
    ).length;
    if (classes >= 4 && new Set(candidate).size >= 12 && shannonEntropy(candidate) >= 4.2) {
      return true;
    }
  }
  return false;
}

function literalSecretRules(value) {
  const rules = new Set();
  for (const rule of tokenRules) {
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(value)) rules.add(rule.name);
  }
  if (sha256(value) === generatedSensitiveLiteralContract.digest) {
    rules.add(generatedSensitiveLiteralContract.category);
  }
  if (hasHighEntropyFamily(value)) rules.add("high-entropy-string");
  return rules;
}

function generatedFallbackAssignmentAllowed(relativePath, normalizedKey, value, form) {
  return (
    relativePath === generatedSensitiveLiteralContract.path &&
    normalizedKey === "DEFAULT_SECRET" &&
    form === generatedSensitiveLiteralContract.form &&
    sha256(value) === generatedSensitiveLiteralContract.digest
  );
}

function scanTypeScript(content, relativePath, findings, enforceGeneratedLiteralContract) {
  const analysis = analyzeTypeScriptStaticValues(content, { relativePath });
  if (analysis.parseErrors > 0) findings.add("typescript-parse-error");
  for (const { key, evaluation, form } of analysis.assignments) {
    const normalizedKey = normalizeAssignmentKey(key);
    if (!isSecretAssignmentKey(normalizedKey)) continue;
    if (evaluation.status === "overflow") {
      findings.add("assigned-secret");
      continue;
    }
    if (
      evaluation.status !== "static" ||
      typeof evaluation.value !== "string" ||
      evaluation.value.length < MIN_ASSIGNMENT_VALUE_CHARS
    ) {
      continue;
    }
    if (
      !isAuditedFixture(relativePath, normalizedKey, evaluation.value) &&
      !generatedFallbackAssignmentAllowed(relativePath, normalizedKey, evaluation.value, form)
    ) {
      findings.add("assigned-secret");
    }
  }

  const observedContractContexts = new Map();
  for (const entry of analysis.staticValues) {
    const digest = sha256(entry.value);
    if (
      entry.form === generatedSensitiveLiteralContract.form &&
      digest === generatedSensitiveLiteralContract.digest
    ) {
      observedContractContexts.set(
        entry.context,
        (observedContractContexts.get(entry.context) ?? 0) + 1,
      );
    }
    for (const rule of literalSecretRules(entry.value)) {
      const reviewedStaticLiteral =
        auditedStaticLiteralAllowances
          .get(relativePath)
          ?.get(rule)
          ?.has(digest) === true;
      const reviewedGeneratedLiteral =
        enforceGeneratedLiteralContract &&
        relativePath === generatedSensitiveLiteralContract.path &&
        rule === generatedSensitiveLiteralContract.category &&
        entry.form === generatedSensitiveLiteralContract.form &&
        generatedSensitiveLiteralContract.contexts.includes(entry.context);
      if (!reviewedStaticLiteral && !reviewedGeneratedLiteral) findings.add(rule);
    }
  }
  if (enforceGeneratedLiteralContract) {
    if (relativePath !== generatedSensitiveLiteralContract.path) {
      findings.add("generated-sensitive-literal-drift");
    } else {
      for (const context of generatedSensitiveLiteralContract.contexts) {
        if (observedContractContexts.get(context) !== 1) {
          findings.add("generated-sensitive-literal-drift");
        }
      }
      if (
        [...observedContractContexts.values()].reduce((total, count) => total + count, 0) !==
        generatedSensitiveLiteralContract.contexts.length
      ) {
        findings.add("generated-sensitive-literal-drift");
      }
    }
  }
}

export function scanBufferForSecrets(
  bytes,
  { enforceGeneratedLiteralContract = false, relativePath = "" } = {},
) {
  if (bytes.length === 0) return [];
  const findings = new Set();
  const representations = decodedRepresentations(bytes);
  for (const { text } of representations) {
    for (const rule of tokenRules) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(text)) findings.add(rule.name);
    }
  }

  if (isJavaScriptPath(relativePath)) {
    const source = representations.find(({ sourceCandidate }) => sourceCandidate);
    if (!source) {
      findings.add("typescript-decode-error");
    } else {
      scanTypeScript(source.text, relativePath, findings, enforceGeneratedLiteralContract);
    }
  } else {
    for (const { text } of representations) {
      for (const assignment of lineAssignments(text)) {
        const normalizedKey = normalizeAssignmentKey(assignment.key);
        if (!isSecretAssignmentKey(normalizedKey)) continue;
        if (isNonliteralLineAssignment(relativePath, assignment)) continue;
        if (assignment.overflow) {
          findings.add("assigned-secret");
        } else if (
          assignment.value.length >= MIN_ASSIGNMENT_VALUE_CHARS &&
          !isAuditedFixture(relativePath, normalizedKey, assignment.value)
        ) {
          findings.add("assigned-secret");
        }
      }
    }
  }
  return [...findings].sort();
}

export function isSensitivePath(relativePath) {
  const normalized = relativePath.replaceAll("\\", "/");
  const basename = path.posix.basename(normalized);
  if (/^\.dev\.vars(?:\..*)?$/i.test(basename)) return true;
  if (/^\.env(?:\..*)?$/i.test(basename)) return true;
  if (/\.(?:der|jks|key|p12|p8|pem|pfx)$/i.test(basename)) return true;
  if (/^(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)$/i.test(basename)) return true;
  if (/^(?:\.git-credentials|\.netrc|\.npmrc|\.pypirc)$/i.test(basename)) return true;
  if (/^(?:credentials?|secrets?)$/i.test(basename)) return true;
  if (
    /^(?:credentials?|secrets?|service[-_.]?account(?:[-_.][a-z0-9_-]+)?|auth[-_.]?config|cloudflare[-_.]?credentials)\.(?:conf|ini|json|properties|toml|ya?ml)$/i.test(
      basename,
    )
  ) {
    return true;
  }
  return normalized === ".docker/config.json" || normalized.endsWith("/.docker/config.json");
}

export function classifyDiagnosticPath(value) {
  const original = String(value ?? "");
  const slashed = original.replaceAll("\\", "/");
  const normalized = path.posix.normalize(slashed || ".");
  const escapesRoot = normalized === ".." || normalized.startsWith("../");
  const secretBearingSegment = slashed
    .split("/")
    .some((segment) => scanBufferForSecrets(Buffer.from(segment, "utf8")).length > 0);
  const unsafe =
    original.length === 0 ||
    /[^\x20-\x7e]/.test(original) ||
    path.posix.isAbsolute(slashed) ||
    /^[A-Za-z]:\//.test(slashed) ||
    escapesRoot ||
    isSensitivePath(normalized) ||
    secretBearingSegment;
  if (unsafe) {
    const digest = createHash("sha256").update(original).digest("hex").slice(0, 16);
    return { display: `[redacted-path:sha256:${digest}]`, normalized, unsafe: true };
  }
  return { display: normalized, normalized, unsafe: false };
}

export function diagnosticPath(value) {
  return classifyDiagnosticPath(value).display;
}

function gitPaths(repoRoot, args) {
  const result = spawnSync("git", args, {
    cwd: repoRoot,
    encoding: "buffer",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) throw new Error("unable to execute repository file enumeration");
  if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed`);
  return result.stdout
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .map((value) => value.replaceAll("\\", "/"));
}

function discoverSensitivePaths(repoRoot, knownPaths) {
  const discovered = [];
  // Git supplies generic tracked/untracked files. This walk enters ignored
  // dependency/build caches only to find sensitive filenames, never to scan
  // their ordinary contents; `.git` alone is excluded completely.
  function walk(directory, prefix = "") {
    let names;
    try {
      names = readdirSync(directory).sort();
    } catch {
      throw new Error(`unable to enumerate repository path: ${diagnosticPath(prefix || ".")}`);
    }
    for (const name of names) {
      if (fullyExcludedDirectories.has(name)) continue;
      const absolute = path.join(directory, name);
      const relative = prefix ? `${prefix}/${name}` : name;
      let stat;
      try {
        stat = lstatSync(absolute);
      } catch {
        throw new Error(`unable to inspect repository path: ${diagnosticPath(relative)}`);
      }
      const sensitive = isSensitivePath(relative);
      if (stat.isSymbolicLink()) {
        if (!knownPaths.has(relative) && sensitive) {
          discovered.push({ absolute, path: relative, category: "sensitive-path", symbolicLink: true });
        }
        continue;
      }
      if (stat.isDirectory()) {
        walk(absolute, relative);
        continue;
      }
      if (stat.isFile() && sensitive && !knownPaths.has(relative)) {
        discovered.push({ absolute, path: relative, category: "ignored-sensitive", symbolicLink: false });
      }
    }
  }
  walk(repoRoot);
  return discovered;
}

export function enumerateWorkingTreeFiles(repoRoot) {
  const tracked = new Set(gitPaths(repoRoot, ["ls-files", "--cached", "-z"]));
  const untracked = new Set(
    gitPaths(repoRoot, ["ls-files", "--others", "--exclude-standard", "-z"]),
  );
  const knownPaths = new Set([...tracked, ...untracked]);
  const files = [];
  for (const relative of [...knownPaths].sort()) {
    const absolute = path.join(repoRoot, ...relative.split("/"));
    let stat;
    try {
      stat = lstatSync(absolute);
    } catch {
      throw new Error(`unable to inspect repository path: ${diagnosticPath(relative)}`);
    }
    if (stat.isDirectory()) continue;
    files.push({
      absolute,
      path: relative,
      category: tracked.has(relative) ? "tracked" : "untracked",
      symbolicLink: stat.isSymbolicLink(),
    });
  }
  files.push(...discoverSensitivePaths(repoRoot, knownPaths));
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

export function scanWorkingTree(repoRoot, { maxFileBytes = DEFAULT_MAX_SCAN_BYTES } = {}) {
  const findings = [];
  for (const file of enumerateWorkingTreeFiles(repoRoot)) {
    if (file.symbolicLink) {
      findings.push({ path: file.path, rule: "symbolic-link" });
      continue;
    }
    let stat;
    try {
      stat = lstatSync(file.absolute);
    } catch {
      findings.push({ path: file.path, rule: "file-read-error" });
      continue;
    }
    if (stat.size > maxFileBytes) {
      findings.push({ path: file.path, rule: "file-too-large-to-scan" });
      continue;
    }
    let bytes;
    try {
      bytes = readFileSync(file.absolute);
    } catch {
      findings.push({ path: file.path, rule: "file-read-error" });
      continue;
    }
    for (const rule of scanBufferForSecrets(bytes, { relativePath: file.path })) {
      findings.push({ path: file.path, rule });
    }
  }
  return findings.sort(
    (left, right) => left.path.localeCompare(right.path) || left.rule.localeCompare(right.rule),
  );
}

export function redactedFindings(findings) {
  return findings
    .map((finding) => `[${String(finding.rule).replace(/[^a-z0-9-]/gi, "?")}] ${diagnosticPath(finding.path)}`)
    .join("\n");
}
