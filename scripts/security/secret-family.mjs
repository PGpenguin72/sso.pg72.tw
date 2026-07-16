import { lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

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

const assignmentPatterns = [
  /^\s*([A-Z][A-Z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)[A-Z0-9_.-]*)\s*[:=]\s*["'`]?([^\s"'`,;}\])]{12,})/gm,
  /["']([A-Z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)[A-Z0-9_.-]*)["']\s*:\s*["'`]([^"'`\r\n]{12,})["'`]/gim,
];

function isPlaceholder(value) {
  const normalized = value.toLowerCase();
  return (
    /(?:placeholder|replace|example|synthetic|dummy|change-?me|fake|fixture|generate-with|local-dast|test(?:-only)?[-_]|vitest|not-a-real|x{4,})/.test(
      normalized,
    ) ||
    normalized.startsWith("${") ||
    normalized.startsWith("<") ||
    normalized.startsWith("your-") ||
    normalized.startsWith("your_")
  );
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

export function scanBufferForSecrets(bytes) {
  const findings = new Set();
  for (const content of representations(bytes)) {
    for (const rule of tokenRules) {
      if (rule.pattern.test(content)) findings.add(rule.name);
    }
    for (const assignmentPattern of assignmentPatterns) {
      assignmentPattern.lastIndex = 0;
      for (let match = assignmentPattern.exec(content); match; match = assignmentPattern.exec(content)) {
        if (!isPlaceholder(match[2])) findings.add("assigned-secret");
      }
    }
  }
  return [...findings].sort();
}

export function isSensitivePath(relativePath) {
  const normalized = relativePath.replaceAll(path.sep, "/");
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

function gitPaths(repoRoot, args) {
  const result = spawnSync("git", args, {
    cwd: repoRoot,
    encoding: "buffer",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) throw result.error;
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
    for (const name of readdirSync(directory).sort()) {
      if (fullyExcludedDirectories.has(name)) continue;
      const absolute = path.join(directory, name);
      const relative = prefix ? `${prefix}/${name}` : name;
      const stat = lstatSync(absolute);
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
      continue;
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
    const stat = lstatSync(file.absolute);
    if (stat.size > maxFileBytes) {
      findings.push({ path: file.path, rule: "file-too-large-to-scan" });
      continue;
    }
    const bytes = readFileSync(file.absolute);
    for (const rule of scanBufferForSecrets(bytes)) findings.push({ path: file.path, rule });
  }
  return findings.sort(
    (left, right) => left.path.localeCompare(right.path) || left.rule.localeCompare(right.rule),
  );
}

export function redactedFindings(findings) {
  return findings.map((finding) => `[${finding.rule}] ${finding.path}`).join("\n");
}
