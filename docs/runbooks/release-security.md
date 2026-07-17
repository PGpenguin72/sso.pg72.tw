# Release Security Assurance

This runbook records the tested source-local boundary for one exact checkout.
The checked-in command/workflow validators permit Wrangler types, local dev, and
`deploy --dry-run` paths, while rejecting deploy and remote-resource commands;
they do not authorize any remote mutation or credential use. Tool installation
and the live advisory check still contact their public download/registry
sources. A passing run is evidence for the exact source, pinned tools, runner
environment, and probes exercised; it is not proof about a compromised
dependency/toolchain or an untested operator command.

## Required Local Gate

From a frozen install at the exact release candidate:

```bash
pnpm check
pnpm security:tools:install
pnpm security:check
pnpm dast:local
```

`pnpm security:check` runs these tracked sub-gates:

| Gate | Command / evidence |
| --- | --- |
| Worker static analysis | Oxlint type-aware `no-floating-promises` and `no-misused-promises` over both Worker implementations |
| Secret scan | required checksum-pinned Gitleaks over complete Git history; explicit bounded/redacted tracked, ordinary-untracked, and ignored-sensitive-filename traversal; TypeScript compiler AST plus bounded line/binary decoding with exact audited allowances; captured Secretlint output |
| Workflow/config | actionlint, immutable Action SHAs, least permissions, code-owned exact workflow/job/step run maps and package-script name/value graph, exact environment scopes, fixed artifact upload, and exact source/generated Wrangler binding targets |
| Dependency policy | live `pnpm audit --json` reconciled field-for-field with `security/accepted-advisories.json` |
| Production artifact | `wrangler deploy --dry-run --outdir` modules plus Static Assets scanned against `security/release-policy.json`, including bounded text/binary secret families |
| Inventory | path-free package/version/license inventory generated from the frozen pnpm install |
| Automation tests | negative advisory, target-allowlist, workflow, config, artifact, and inventory tests |

CI first runs `pnpm check`, installs actionlint and Gitleaks from the exact
versions and SHA-256 checksums in `security/tool-versions.json`, then runs the
security and local DAST gates. Every third-party Action is pinned to the
immutable commit recorded in the same file. The checked-in upload step selects
only `.artifacts/release`, errors when it is absent, excludes hidden files, and
uses seven-day retention; the dry-run bundle and temporary D1 state are outside
that selected path.

The npm tools are exact-pinned in `package.json` and the lockfile. Type-aware
analysis uses `oxlint-tsgolint@0.24.0`, the newest release old enough to satisfy
the workspace release-age policy; the newly published `0.25.0` was deliberately
not exempted from that policy.

The release policy fixes every binding type, name, and resource target: the
reviewed non-working D1 UUID placeholder/database name, Queue producer,
consumer, DLQ and retry/batch/timeout values, every Rate Limit namespace and
limit/period, route, Assets behavior, vars, and required secret *names*. Both
source JSONC and the Vite-generated config must match exactly. The inventory
records that typed contract plus module/asset allowlists, hashes, and byte
limits. It rejects `.map`, `.dev.vars`, key files, private machine paths,
embedded text or binary credential families, symlinks, and unexpected files.
Generated config path metadata is validated in place and is outside the current
artifact upload allowlist.

`security/workflow-policy.json` default-denies environment keys at workflow,
job, and step scope. Policy may select only the code-owned `DAST_*` expressions
and exact `CI=1`/`NO_COLOR=1` values; it cannot add workflow commands, leaf
commands, local scripts, or package-script approvals. Every workflow job/step
run string and every recursively reachable package-script name and complete
value is fixed in code. CRLF is normalized, but quote composition, inline env,
network tools, redirects, extra commands, environment-file writes, and control
characters cannot equal that map and fail closed. All `CLOUDFLARE_*`, legacy
`CF_*`, and `WRANGLER_*` keys are code-owned hard denials. Preview DAST therefore
accepts its three non-credential `DAST_*` variables, not a Cloudflare API
credential.

The explicit working-tree scanner obtains tracked and ordinary untracked files
from Git, then traverses ignored dependency/build-cache trees only to find
sensitive filenames such as root/nested `.dev.vars*`, `.env*`, key/PEM and
credential configuration paths. `.git` is excluded. Files larger than the
bounded scan limit and symlinks fail closed. JavaScript and TypeScript are
parsed by the pinned TypeScript compiler AST. A depth/segment/length-bounded
static evaluator handles string literals, no-substitution and all-static
templates, binary `+`, parentheses, and static assertion wrappers before
normalizing declaration/property keys. The separate bounded line/dotenv parser
supports `export`, `const`, `let`, and `var`. UTF-8, UTF-16LE/BE, and
NUL-interleaved printable representations share private-key, assignment, known
token, and high-entropy checks. Nonliteral expressions are not embedded bytes.
Source fixtures, generated error/format metadata, and PGID token prefixes are
exempt only by exact path/key/value or digest contracts. Better Auth's bundled
default-secret fallback is different: the generated Worker must contain exactly
three reviewed string literals with the exact digest and AST contexts. Removing,
replacing, concatenating, templating, or adding an occurrence fails. Words such
as `test`, `example`, or `placeholder` have no special meaning. PGID's source and
generated config contracts separately require `BETTER_AUTH_SECRET`; the fallback
allowance is not evidence for an untested runtime path if that requirement later
changes. Findings expose a
rule and a normalized safe relative path, never matching bytes. Sensitive,
secret-bearing, absolute/outside, control-character, and other terminal-unsafe
paths are replaced with a short SHA-256 identifier across working-tree and
artifact diagnostics. Gitleaks is mandatory; run
`pnpm security:tools:install` first on a new checkout.

The dependency/license inventory is platform-specific because pnpm installs
only the optional native packages for the current runner. Linux CI evidence and
a macOS local inventory can therefore differ in optional package rows while
remaining derived from the same frozen lockfile.

## Advisory Acceptance

`security/accepted-advisories.json` is the only waiver input. Each entry must
name the exact GHSA, package, installed version, severity, title/ranges, rationale,
at least two compensating controls, owner, acceptance date, expiry, and review
command. The checker enforces a maximum 180-day duration. It fails when:

- a live advisory is unrecorded or any recorded field/version changes;
- a record expires or remains after the advisory disappears;
- the package manifest no longer exact-pins the recorded version;
- a High or Critical finding appears.

The current accepted Moderate expires on 2026-10-16. Review it with the recorded
`pnpm audit --json` command and update/remove the record only in a reviewed
source change. Do not add an audit ignore.

## Local DAST

`pnpm dast:local` owns the entire test lifecycle:

1. It checks that fixed loopback ports `5173` and `5174` are free.
2. It builds PGID, creates two temporary persistence directories, and applies
   SSO/test-RP migrations locally.
3. It starts both Workers with `wrangler dev --local` and command-line synthetic
   values. The runner removes `CLOUDFLARE_*`, `WRANGLER_OAUTH_TOKEN`, and
   credential-suffixed inherited variables; use a clean local shell because the
   test does not assert that every unrelated host variable is absent.
4. It probes health/readiness, discovery/JWKS, public OIDC error behavior,
   resource-indicator rejection, dynamic-registration denial, logout/admin
   denial, cache/security headers, CSRF rejection, and test-RP error handling.
5. A `finally` block terminates both process groups and deletes the temporary
   persistence root.

The currently tested scanner accepts only canonical literal
`http://127.0.0.1:5173` and
`http://127.0.0.1:5174`; `localhost`, DNS, IPv6, credentials, paths, queries and
other ports fail. Requests cannot override Host/forwarding headers and use
manual redirect handling. The asserted 15 PGID and two test-RP probes construct
no cookies, bearer tokens, client secrets, OAuth codes, Passkey data, or user
credentials. Passing this set does not cover real Google/Passkey login, consent,
authenticated admin mutations, rate exhaustion, destructive behavior, load, or
an unreviewed future probe.

## Isolated Preview

The `Isolated Preview DAST` workflow is `workflow_dispatch` only and uses the
GitHub environment named `isolated-preview`. Its job-level repository guard
requires both `github.actor` and `github.triggering_actor` to be owner
`PGpenguin72` and requires `github.ref` to be `refs/heads/main`; an environment
reviewer is additional protection, not the repository authorization source.
Before an owner runs it, protect that environment and configure:

| Variable | Required value |
| --- | --- |
| `PGID_DAST_PREVIEW_ORIGIN` | Exact isolated origin matching `https://pg72-id-preview.<preview-account-subdomain>.workers.dev` |
| `PGID_DAST_PREVIEW_OPT_IN` | `owner-approved-isolated-preview` |

The same exact origin must also be committed as `preview.approvedOrigin` in
`security/dast-policy.json`. It is currently `null` because no actual isolated
hostname has been owner-approved; this deliberately fails the authorization
step before any DAST HTTP request. Do not replace it with a wildcard or workflow
input. The hostname must retain the exact `pg72-id-preview` project prefix and
`workers.dev` shape. The scanner rejects `https://sso.pg72.tw`, custom domains,
Pages, lookalikes, non-HTTPS/non-default ports, credentials, and paths. Preview
must use a separate Cloudflare account, D1, secrets, queues, rate-limit
namespaces, and synthetic identities. No Preview run was performed by this
change.

This manual credential-free Preview baseline still does not complete the
`codex.md` section 9.2 DAST gate. Full Production GO needs independently
reviewed authenticated login/consent/admin/gateway/logout coverage, appropriate
non-destructive Preview fixtures, and retained owner-approved evidence.

## Tool Sources

- [Cloudflare Worker bundling and dry-run output](https://developers.cloudflare.com/workers/wrangler/bundling/)
- [Wrangler deploy command](https://developers.cloudflare.com/workers/wrangler/commands/workers/#deploy)
- [Cloudflare Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/)
- [Oxlint type-aware analysis](https://oxc.rs/docs/guide/usage/linter/type-aware.html)
- [Gitleaks releases](https://github.com/gitleaks/gitleaks/releases)
- [actionlint releases](https://github.com/rhysd/actionlint/releases)
