import { lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

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
const assignmentDeclarationSource =
  "(?:(?:export[\\t ]+const|const|let|var)[\\t ]+)?";
const bareAssignmentKeySource = "([A-Za-z_$][A-Za-z0-9_$./@-]{0,127})";

function escapedDelimiter(quote) {
  return quote === "`" ? "\\`" : quote;
}

const assignmentKeySources = [
  ...['"', "'", "`"].map((quote) => {
    const delimiter = escapedDelimiter(quote);
    return `${delimiter}((?:\\\\[^\\r\\n]|(?!${delimiter})[^\\r\\n]){1,128})${delimiter}`;
  }),
  bareAssignmentKeySource,
];

function assignmentPrefixSource(keySource) {
  return `^[\\t ]*${assignmentDeclarationSource}${keySource}[\\t ]*[:=][\\t ]*`;
}

const quotedAssignmentPatterns = assignmentKeySources.flatMap((keySource) =>
  ['"', "'", "`"].map((quote) => {
    const delimiter = escapedDelimiter(quote);
    return {
      pattern: new RegExp(
        `${assignmentPrefixSource(keySource)}${delimiter}((?:\\\\[\\s\\S]|(?!${delimiter})[\\s\\S]){${MIN_ASSIGNMENT_VALUE_CHARS},${MAX_ASSIGNMENT_VALUE_CHARS}})${delimiter}[\\t ]*[,;]?[\\t ]*(?:(?:#|//).*)?$`,
        "gm",
      ),
      quote,
    };
  }),
);
const oversizedQuotedAssignmentPatterns = assignmentKeySources.flatMap((keySource) =>
  ['"', "'", "`"].map((quote) => {
    const delimiter = escapedDelimiter(quote);
    return new RegExp(
      `${assignmentPrefixSource(keySource)}${delimiter}(?:\\\\[\\s\\S]|(?!${delimiter})[\\s\\S]){${MAX_ASSIGNMENT_VALUE_CHARS + 1}}`,
      "gm",
    );
  }),
);
const unquotedAssignmentPatterns = assignmentKeySources.map(
  (keySource) =>
    new RegExp(
      `${assignmentPrefixSource(keySource)}([^\\r\\n]{${MIN_ASSIGNMENT_VALUE_CHARS},${MAX_ASSIGNMENT_VALUE_CHARS}})$`,
      "gm",
    ),
);
const oversizedUnquotedAssignmentPatterns = assignmentKeySources.map(
  (keySource) =>
    new RegExp(
      `${assignmentPrefixSource(keySource)}[^\\r\\n]{${MAX_ASSIGNMENT_VALUE_CHARS + 1}}`,
      "gm",
    ),
);
const binaryAssignmentPattern = new RegExp(
  `(?:^|[\\x00\\r\\n])(?:(?:export[\\x00\\t ]+const|const|let|var)[\\x00\\t ]+)?${bareAssignmentKeySource}[\\x00\\t ]{0,8}[:=][\\x00\\t ]{0,8}([^\\x00\\r\\n]{${MIN_ASSIGNMENT_VALUE_CHARS},${MAX_ASSIGNMENT_VALUE_CHARS}})`,
  "gm",
);

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
      ["DEFAULT_SECRET", "better-auth-secret-12345678901234567890"],
      ["PEM_CONVERTER_PRIVATE_KEY_TAG", "PRIVATE KEY"],
      ["CHALLENGE_PASSWORD_ATTRIBUTE_NAME", "Challenge Password"],
      ["CLIENT_SECRET_PREFIX", "pg72_cs_"],
      ["OPAQUE_ACCESS_TOKEN", "pg72_at_"],
      ["REFRESH_TOKEN", "pg72_rt_"],
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
    auditedAssignmentAllowances.get(relativePath)?.get(normalizedKey)?.has(value) === true
  );
}

function unquotedValue(value) {
  return value
    .replace(/[\t ]+(?:#|\/\/).*$/, "")
    .replace(/[\t ]*[,;][\t ]*$/, "")
    .trim();
}

function assignments(content) {
  const matches = [];
  for (const { pattern, quote } of quotedAssignmentPatterns) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(content); match; match = pattern.exec(content)) {
      matches.push({
        normalizedKey: normalizeAssignmentKey(match[1]),
        quotedValue: true,
        valueQuote: quote,
        value: match[2],
      });
    }
  }
  for (const pattern of unquotedAssignmentPatterns) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(content); match; match = pattern.exec(content)) {
      const value = unquotedValue(match[2]);
      if (value.length >= MIN_ASSIGNMENT_VALUE_CHARS && !/^["'`]/.test(value)) {
        matches.push({ normalizedKey: normalizeAssignmentKey(match[1]), quotedValue: false, value });
      }
    }
  }
  binaryAssignmentPattern.lastIndex = 0;
  for (
    let match = binaryAssignmentPattern.exec(content);
    match;
    match = binaryAssignmentPattern.exec(content)
  ) {
    if (match[0].includes("\0")) {
      matches.push({
        normalizedKey: normalizeAssignmentKey(match[1]),
        quotedValue: false,
        value: unquotedValue(match[2]),
      });
    }
  }
  return matches;
}

function oversizedAssignmentKeys(content) {
  const normalizedKeys = [];
  for (const pattern of [
    ...oversizedQuotedAssignmentPatterns,
    ...oversizedUnquotedAssignmentPatterns,
  ]) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(content); match; match = pattern.exec(content)) {
      normalizedKeys.push(normalizeAssignmentKey(match[1]));
    }
  }
  return normalizedKeys;
}

function representations(bytes) {
  const raw = bytes.toString("latin1");
  const printable = [];
  let current = "";
  for (const byte of bytes) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= 4) printable.push(current);
      current = "";
    }
  }
  if (current.length >= 4) printable.push(current);
  return [raw, printable.join("\n"), raw.replace(/[^\x09\x0a\x0d\x20-\x7e]+/g, "\n")];
}

function isCodeLikePath(relativePath) {
  return /\.(?:[cm]?[jt]sx?|jsonc?|patch|sql)$/i.test(relativePath);
}

function isNonliteralAssignment(relativePath, quotedValue, valueQuote, value) {
  if (quotedValue) {
    return isCodeLikePath(relativePath) && valueQuote === "`" && value.includes("${");
  }
  if (/\$\(|\$\{|^(?:await|new)\b|=>/.test(value)) return true;
  if (!isCodeLikePath(relativePath)) return false;
  return (
    /^(?:true|false|null|undefined|void|[+-]?(?:\d+\.?\d*|\.\d+))$/.test(value) ||
    /^[a-z_$][A-Za-z0-9_$]*$/.test(value) ||
    /^(?=[A-Za-z0-9_$]*[a-z])[A-Z][A-Za-z0-9_$]*$/.test(value) ||
    /^[A-Z][A-Z0-9]*_[A-Z0-9_]+$/.test(value) ||
    /^![A-Za-z_$][A-Za-z0-9_$]*$/.test(value) ||
    /^[A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*)+$/.test(value) ||
    /(?:===?|!==?|<=|>=|\?|&&|\|\||[.()[\]{}]|^!|\s[|&+*/-]\s)/.test(value)
  );
}

export function scanBufferForSecrets(bytes, { relativePath = "" } = {}) {
  const findings = new Set();
  for (const content of representations(bytes)) {
    for (const rule of tokenRules) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(content)) findings.add(rule.name);
    }
    if (oversizedAssignmentKeys(content).some(isSecretAssignmentKey)) {
      findings.add("assigned-secret");
    }
    for (const { normalizedKey, quotedValue, valueQuote, value } of assignments(content)) {
      if (!isSecretAssignmentKey(normalizedKey)) continue;
      if (isNonliteralAssignment(relativePath, quotedValue, valueQuote, value)) continue;
      if (!isAuditedFixture(relativePath, normalizedKey, value)) {
        findings.add("assigned-secret");
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
