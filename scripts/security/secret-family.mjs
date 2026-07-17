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

const secretKeySource =
  "[A-Z][A-Z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)[A-Z0-9_.-]*";
const assignmentPrefix =
  `^[\\t ]*(?:["'\\\`](${secretKeySource})["'\\\`]|(${secretKeySource}))[\\t ]*[:=][\\t ]*`;
const quotedAssignmentPatterns = ['"', "'", "`"].map((quote) => {
  const escapedQuote = quote === "`" ? "\\`" : quote;
  return new RegExp(
    `${assignmentPrefix}${escapedQuote}((?:\\\\[\\s\\S]|(?!${escapedQuote})[\\s\\S]){8,4096})${escapedQuote}[\\t ]*[,;]?[\\t ]*(?:(?:#|//).*)?$`,
    "gim",
  );
});
const oversizedQuotedAssignmentPatterns = ['"', "'", "`"].map((quote) => {
  const escapedQuote = quote === "`" ? "\\`" : quote;
  return new RegExp(
    `${assignmentPrefix}${escapedQuote}(?:\\\\[\\s\\S]|(?!${escapedQuote})[\\s\\S]){4097}`,
    "gim",
  );
});
const unquotedAssignmentPattern = new RegExp(
  `^[\\t ]*(?:["'\\\`](${secretKeySource})["'\\\`]|(${secretKeySource}))[\\t ]*[:=][\\t ]*([^\\r\\n]{8,4096})$`,
  "gim",
);
const oversizedUnquotedAssignmentPattern = new RegExp(
  `${assignmentPrefix}[^\\r\\n]{4097}`,
  "gm",
);
const binaryAssignmentPattern = new RegExp(
  `(?:^|[\\x00\\r\\n])(${secretKeySource})[\\x00\\t ]{0,8}[:=][\\x00\\t ]{0,8}([^\\x00\\r\\n]{8,4096})`,
  "gm",
);

// These reviewed source fixtures and generated error enums are not substring
// heuristics. An allowance applies only when path, key, and complete value match.
const auditedAssignmentAllowances = new Map([
  [
    "apps/sso/.dev.vars.example",
    new Map([
      ["BETTER_AUTH_SECRET", "generate-with-openssl-rand-base64-32"],
      ["GOOGLE_CLIENT_SECRET", "replace-with-google-oauth-client-secret"],
      ["TURNSTILE_SECRET_KEY", "replace-with-turnstile-secret-key"],
    ]),
  ],
  [
    "apps/sso/vitest.config.ts",
    new Map([
      ["BETTER_AUTH_SECRET", "test-only-better-auth-secret-0000000000000000"],
      ["GOOGLE_CLIENT_SECRET", "test-only-google-secret"],
      ["TURNSTILE_SECRET_KEY", "test-only-turnstile-secret"],
      ["TELEGRAM_BOT_TOKEN", "123456:AAvitest-telegram-bot-token"],
    ]),
  ],
  [
    "apps/sso/test/registration.spec.ts",
    new Map([
      ["GITHUB_CLIENT_SECRET", "test-github-client-secret"],
      ["TURNSTILE_SECRET_KEY", "undefined"],
    ]),
  ],
  [
    "apps/sso/worker/auth.cli.ts",
    new Map([
      ["BETTER_AUTH_SECRET", "cli-only-placeholder-secret-at-least-32-characters"],
      ["GOOGLE_CLIENT_SECRET", "cli-placeholder"],
    ]),
  ],
  [
    "wiki/developers/register-client.md",
    new Map([["OIDC_CLIENT_SECRET", "pg72_cs_xxxxxxxx"]]),
  ],
  [
    "artifact:worker/index.js",
    new Map([
      ["INVALID_PASSWORD", "Invalid password"],
      ["INVALID_EMAIL_OR_PASSWORD", "Invalid email or password"],
      ["INVALID_TOKEN", "Invalid token"],
      ["ID_TOKEN_NOT_SUPPORTED", "id_token not supported"],
      [
        "USER_ALREADY_HAS_PASSWORD",
        "User already has a password. Provide that to delete the account.",
      ],
    ]),
  ],
]);

function normalizedRelativePath(value) {
  return typeof value === "string" ? value.replaceAll("\\", "/") : "";
}

function isAuditedFixture(relativePath, key, value) {
  return auditedAssignmentAllowances.get(normalizedRelativePath(relativePath))?.get(key) === value;
}

function unquotedValue(value) {
  return value
    .replace(/[\t ]+(?:#|\/\/).*$/, "")
    .replace(/[\t ]*[,;][\t ]*$/, "")
    .trim();
}

function assignments(content) {
  const matches = [];
  for (const pattern of quotedAssignmentPatterns) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(content); match; match = pattern.exec(content)) {
      const key = match[1] ?? match[2];
      if (match[1] !== undefined || key === key.toUpperCase()) {
        matches.push({ key, value: match[3] });
      }
    }
  }
  unquotedAssignmentPattern.lastIndex = 0;
  for (
    let match = unquotedAssignmentPattern.exec(content);
    match;
    match = unquotedAssignmentPattern.exec(content)
  ) {
    const value = unquotedValue(match[3]);
    const key = match[1] ?? match[2];
    if (
      value.length >= 8 &&
      !/^["'`]/.test(value) &&
      (match[1] !== undefined || key === key.toUpperCase())
    ) {
      matches.push({ key, value });
    }
  }
  binaryAssignmentPattern.lastIndex = 0;
  for (
    let match = binaryAssignmentPattern.exec(content);
    match;
    match = binaryAssignmentPattern.exec(content)
  ) {
    if (match[0].includes("\0")) {
      matches.push({ key: match[1], value: unquotedValue(match[2]) });
    }
  }
  return matches;
}

function hasOversizedAssignment(content) {
  for (const pattern of [...oversizedQuotedAssignmentPatterns, oversizedUnquotedAssignmentPattern]) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(content); match; match = pattern.exec(content)) {
      const key = match[1] ?? match[2];
      if (match[1] !== undefined || key === key.toUpperCase()) return true;
    }
  }
  return false;
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

export function scanBufferForSecrets(bytes, { relativePath = "" } = {}) {
  const findings = new Set();
  for (const content of representations(bytes)) {
    if (hasOversizedAssignment(content)) findings.add("assigned-secret");
    for (const rule of tokenRules) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(content)) findings.add(rule.name);
    }
    for (const { key, value } of assignments(content)) {
      if (!isAuditedFixture(relativePath, key, value)) findings.add("assigned-secret");
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
