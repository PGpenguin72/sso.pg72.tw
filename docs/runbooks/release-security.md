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

Automatic push/pull-request CI runs from a frozen install at the exact release
candidate:

```bash
pnpm check
pnpm security:tools:install
pnpm security:check
```

Automatic CI excludes DAST. Before Production GO, the owner must separately
authorize and retain the credential-free exact-candidate baseline:

```bash
pnpm dast:local
```

This owner-authorized local DAST evidence is required but does not satisfy the
still-pending authenticated isolated-Preview DAST gate.

`pnpm security:check` runs these tracked sub-gates:

| Gate | Command / evidence |
| --- | --- |
| Worker static analysis | Oxlint type-aware `no-floating-promises` and `no-misused-promises` over both Worker implementations |
| Secret scan | required checksum-pinned Gitleaks over complete Git history; explicit bounded/redacted tracked, ordinary-untracked, and ignored-sensitive-filename traversal; TypeScript compiler AST plus bounded line/binary decoding with exact audited allowances; captured Secretlint output |
| Workflow/config | pre-install stdlib identity for exact workflow/manifests/pnpm policy/lockfile/patches and absent repo pnpm hooks/config/implicit native builds/install state; later raw-byte workflow identity, actionlint, immutable Action SHAs, least permissions, exact run maps, complete and reachable package-script digests with lifecycle expansion, exact environment scopes, fixed artifact upload, and exact source/generated Wrangler targets |
| Dependency policy | live `pnpm audit --json` reconciled field-for-field with `security/accepted-advisories.json` |
| Production artifact | code-owned whole-entry SHA-256 followed by `wrangler deploy --dry-run --outdir` module/Static Asset policy and bounded text/binary secret-family scans |
| Inventory | path-free package/version/license inventory generated from the frozen pnpm install |
| Automation tests | negative advisory, target-allowlist, workflow, config, artifact, and inventory tests |

Immediately after checkout, CI and Preview run
`node scripts/security/release-identity.mjs` using only Node standard-library
modules. This occurs before Preview authorization, pnpm setup/install,
`pnpm check`, or any other repository script. It fixes the exact workflow file
set/bytes, all four package-manifest and complete script-map identities, and
the raw pnpm workspace lifecycle/build policy. It additionally requires
`pnpm-lock.yaml` to be an exact regular non-symlink file, requires `patches/`
to be a regular non-symlink directory containing exactly `README.md` and the
reviewed `@better-auth__oauth-provider@1.6.23.patch` at their code-owned raw
digests, and rejects `.pnpmfile.mjs`, `.pnpmfile.cjs`, or a project `.npmrc`
at the root or any code-owned package root. It also rejects `binding.gyp` and
pre-existing `node_modules` at all four roots, regardless of whether the path
is a file, directory, symlink, or unreadable. CI then runs `pnpm check`,
installs actionlint and Gitleaks from the exact
versions and SHA-256 checksums in `security/tool-versions.json`, then runs the
security gate. It does not invoke DAST. Every third-party Action is pinned to the
immutable commit recorded in the same file. The checked-in upload step selects
only `.artifacts/release`, errors when it is absent, excludes hidden files, and
uses seven-day retention; the dry-run bundle and temporary D1 state are outside
that selected path. The automatic CI artifact contains source-assurance
inventories, not DAST evidence.

This boundary follows pnpm's documented
[`--frozen-lockfile`](https://pnpm.io/11.x/cli/install#--frozen-lockfile),
[pnpmfile](https://pnpm.io/11.x/pnpmfile),
[project `.npmrc`](https://pnpm.io/11.x/npmrc), and
[patch](https://pnpm.io/11.x/cli/patch-commit) behavior, plus npm's documented
[`binding.gyp` default install lifecycle](https://docs.npmjs.com/cli/using-npm/scripts#life-cycle-operation-order).
Inspection of the pinned pnpm 11.5.0 bundle confirms that the default workspace
hook lookup tries `.pnpmfile.mjs` and then the legacy `.pnpmfile.cjs`; it does
not recognize a default `.pnpmfile.js`. The same source reads the workspace-root
`.npmrc`, not per-package `.npmrc` files, but all four package roots are denied
to preserve a single reviewed absent-config rule.

The pinned lifecycle runner synthesizes `node-gyp rebuild` for the `install`
stage when a package root contains `binding.gyp` and its exact manifest has no
explicit `preinstall` or `install`. Its adjacent `server.js` default applies
only to an explicitly requested `start`, which neither release workflow invokes.
It also probes `<project node_modules>/.hooks/<stage>`; requiring every
code-owned `node_modules` path to be absent at checkout closes that implicit
install path before pnpm runs.

Pnpm can also install
[`configDependencies`](https://pnpm.io/11.x/config-dependencies) before regular
dependencies and automatically load plugin `pnpmfile.mjs`/`pnpmfile.cjs`
files. The exact `pnpm-workspace.yaml` contract contains no such dependency, so
that path is closed. Pnpm supports `package.json5` and `package.yaml` fallback
manifests, but each code-owned package has a required exact `package.json`,
which pnpm 11.5.0 selects first. The checker now proves the initial checkout has
no package-root `node_modules`; generated current lock/workspace state exists
only after this boundary runs. User/global pnpm configuration or global
pnpmfiles, command line/runner environment, the pnpm store, registry
metadata/tarballs, and the Node/pnpm binaries remain outside this
repository-byte identity. Release evidence therefore still requires a trusted,
isolated runner; this checker does not prove those external inputs uncompromised.

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

The production Wrangler entry module is deterministic for the pinned toolchain
and must match a SHA-256 constant owned by `scripts/security/artifact-gate.mjs`.
The identity check runs before the existing structural and AST scans, so a
replacement, decoy, duplicate, removal, concatenation, template rewrite, or any
other entry-byte change fails even if a shallow structural pattern still looks
reviewed. The artifact gate first requires each code-owned package's
`node_modules` to be a local directory and recursively rejects any installed
dependency symlink whose realpath leaves the checkout. This matters because
Rolldown retains module-provenance comments; reusing another worktree's module
tree changes those comments and the derived chunk hashes even when source is
identical. The gate hashes raw, unminified deployed bytes and continues to reject
source maps; it does not strip runtime or provenance sections. Do not derive or
update the entry constant automatically. An intentional runtime, dependency,
bundler, or build-chain change must receive human review; then run two
independent frozen installs, clean builds, and Wrangler dry-runs, confirm the
entry and every emitted Worker chunk are byte-identical, and update the constant
in the reviewed change. The current local-candidate entry and all eleven Worker
chunks were byte-identical across two different local checkout paths with
independent local installs. That topology proof does not authorize updating the
code-owned digest before all later runtime inputs freeze and the owner reviews
the final candidate. Linux equality has not been measured; this is an open
evidence gap, not evidence of a mismatch.

`security/workflow-policy.json` default-denies environment keys at workflow,
job, and step scope. Policy may select only the code-owned `DAST_*` expressions
and exact `CI=1`/`NO_COLOR=1` values; it cannot add workflow commands, leaf
commands, local scripts, or package-script approvals. Every workflow job/step
run string is fixed in code. Every complete workspace `scripts` object is bound
to one canonical SHA-256 in addition to the recursively reachable graph. The
command model expands pnpm's implicit `pre*` and `post*` hooks for every invoked
root/filtered script and scans `preinstall`, `install`, `postinstall`, and
`prepare` for every code-owned workspace during frozen install. The exact
`ci.yml` and `dast-preview.yml` raw LF bytes have code-owned SHA-256 identities;
CRLF conversion and every action/input/job/step/comment change fail before YAML
and deeper semantic checks. Quote composition, inline env, network tools,
redirects, extra commands, environment-file writes, and control characters also
fail the retained structural layer. All `CLOUDFLARE_*`, legacy `CF_*`, and
`WRANGLER_*` keys are code-owned hard denials. Preview DAST therefore
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

## Production Version Evidence Model

`scripts/security/production-version-upload-gate.mjs` is currently an
`OFFLINE_MODEL_ONLY`, structurally non-executable model. Its production entry
fails before any remote adapter or child process can run. Ordinary GitHub CI,
package scripts, workflow commands, and local-script allowlists do not expose a
direct command for it. An offline model result is never production deploy
evidence and does not authorize version promotion, traffic changes, routes,
triggers, or DAST.

The adjacent adapter is also a non-executable source model. It accepts only
bounded duplicate-aware JSON bytes and has no transport, credential, socket, or
mutation method. It requires the exact account and Worker target on every
observation, standard success/error/message response envelopes, closed
multi-page result metadata, one ordered endpoint set, bounded observation
times, and recomputed pairing across routes, custom domains, schedules, Queue
consumers, and Queue triggers. Unordered collections are canonicalized with a
locale-independent ordering while semantic version order is preserved and
validated. Duplicate semantic routes, domains, bindings, schedules, or Queue
identities fail closed. If the complete inventory cannot fit the adapter's
bounded input, the operation must stop; truncation is not an accepted snapshot.

Those checks establish only a normalized source schema. They do not prove API
permission coverage, response provenance, cross-endpoint atomicity, single-
writer custody, or that an opaque correlation/token digest came from the owner.
The normalized snapshot and every receipt therefore keep those verification
fields false. External C must still compare the endpoint/result shapes and
pagination behavior with the actual Cloudflare API before any activation
proposal.

No custody validator or wrapper candidate is retained in this slice. The
attempted custody schema could not yet represent the gate's split generated-dir
config and private-temp output layout, a complete Node/ELF plus transitive
JS/native/WASM execution closure, or every child executable/argument/
environment/cwd identity without vacuous graph declarations. That is an
explicit representability stop, not accepted residual evidence. A future
immutable task must solve and independently review those contracts before a
data-only wrapper can be reconsidered; production execution remains blocked.

A future Workers Builds production command must invoke a separately reviewed
gate that can upload only an inactive version. That path remains blocked on all
of the following:

- external-C review of the normalized Cloudflare API adapter;
- multi-endpoint snapshot provenance, permission coverage, atomicity, and
  single-writer review;
- owner review of the Workers Builds trigger and token custody;
- a reviewed owner-acceptance issuance/provenance channel for pinned Wrangler's
  bounded internal version-create retries;
- complete child-process-tree custody;
- a sealed identity for Wrangler's executable dependency closure;
- a normalized script-content manifest and provenance proof that correlates an
  observed server ETag with the reviewed local artifact;
- trusted Git binary and configuration custody.

Pinned Wrangler 4.110.0 still retries some internal API failures during
`versions upload`; pinning its package, CLI, and launcher files does not remove
that behavior or identify all transitively loaded executable bytes. The offline
model accepts only an exact, maximum-24-hour owner record for `PGpenguin72`,
`pg72-id`, one candidate commit/tree, one redacted production-target binding,
the pinned Wrangler identities, at most three version-create attempts, and at
most two duplicate inactive versions. Its `current-workers-build` selector is
resolved against one canonical Workers Build UUID and binds only that UUID's
SHA-256 into the receipt. It is not evidence that the owner pre-approved the
server-assigned UUID. Retrigger replay, input injection, issuance provenance,
and build/token custody remain production blockers.

The same pinned CLI defines the hidden global `experimental-provision` and
`experimental-auto-create` booleans with `true` defaults. The reviewed upload
argument model therefore fixes `--experimental-provision=false` and
`--experimental-auto-create=false` exactly once; callers cannot omit, enable,
duplicate, or replace them with aliases. A missing D1 or Queue resource must
stop the operation before version creation and must never be provisioned by the
upload command.

The private config's `workers_dev=false` and `preview_urls=false` values are
artifact equality constraints, not mutations of live Worker subdomain
settings. Before any version-create POST, an independently bound live preflight
must prove workers.dev `enabled=false` and Preview URLs
`previews_enabled=false` for the exact account and Worker. Any mismatch or
unprovable state stops the lane; `--strict` and the private config do not replace
that proof or authorize changing either live setting.

For one to three added versions, every normalized detail must retain the exact
candidate tag/message, runtime, binding and secret-name inventory, remain
inactive, and share one observed script ETag. Only an exact successful output
for the newest added version yields `VERIFIED_INACTIVE_VERSION`. Missing output
or a nonzero child result with fully verified inactive additions yields
`REVIEW_REQUIRED`; zero additions yields
`NO_MUTATION_RETRY_REQUIRES_OWNER`. Neither result retries, deletes, promotes,
deploys, or changes triggers. Observed ETag equality does not prove local
artifact identity, so the receipt records its hash and keeps
`scriptArtifactIdentityVerified=false`.

Wrangler's separate content-addressed asset retry is also unresolved. The model
does not claim asset identity or idempotency without a reviewed normalized
adapter and exact manifest proof. Until every blocker above is closed in
reviewed source, this model must remain a production NO-GO and no runnable
production command may be published.

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
