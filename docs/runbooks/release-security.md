# Release Security Assurance

This runbook describes source-only release gates. None of these commands deploys
a Worker, touches remote D1/Queue state, provisions a client, or sends real
credentials.

## Required Local Gate

From a frozen install at the exact release candidate:

```bash
pnpm check
pnpm security:check
pnpm dast:local
```

`pnpm security:check` runs these tracked sub-gates:

| Gate | Command / evidence |
| --- | --- |
| Worker static analysis | Oxlint type-aware `no-floating-promises` and `no-misused-promises` over both Worker implementations |
| Secret scan | Gitleaks over complete Git history when installed; exact-pinned Secretlint working-tree fallback on unsupported/offline local machines |
| Workflow/config | actionlint when installed, deterministic YAML semantics, immutable Action SHAs, least permissions, concurrency, retention, Wrangler JSON Schema, and exact binding/config policy |
| Dependency policy | live `pnpm audit --json` reconciled field-for-field with `security/accepted-advisories.json` |
| Production artifact | `wrangler deploy --dry-run --outdir` modules plus Static Assets scanned against `security/release-policy.json` |
| Inventory | path-free package/version/license inventory generated from the frozen pnpm install |
| Automation tests | negative advisory, target-allowlist, workflow, config, artifact, and inventory tests |

CI first runs `pnpm check`, installs actionlint and Gitleaks from the exact
versions and SHA-256 checksums in `security/tool-versions.json`, then runs the
security and local DAST gates. Every third-party Action is pinned to the
immutable commit recorded in the same file. CI retains only
`.artifacts/release/` for seven days; it does not retain the dry-run bundle or
temporary D1 state.

The npm tools are exact-pinned in `package.json` and the lockfile. Type-aware
analysis uses `oxlint-tsgolint@0.24.0`, the newest release old enough to satisfy
the workspace release-age policy; the newly published `0.25.0` was deliberately
not exempted from that policy.

The release artifact inventory confirms the entrypoint, exact production route,
vars, required secret *names*, D1/Queue/Rate Limit/Assets bindings, module and
asset allowlists, hashes, and byte limits. It rejects `.map`, `.dev.vars`, key
files, private machine paths, embedded credential patterns, symlinks, and
unexpected files. The generated Vite Wrangler config itself contains local
build-tool path metadata and is therefore validated in place but never uploaded
as CI evidence.

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
3. It starts both Workers with `wrangler dev --local`, synthetic placeholder
   values, and no real credentials.
4. It probes health/readiness, discovery/JWKS, public OIDC error behavior,
   resource-indicator rejection, dynamic-registration denial, logout/admin
   denial, cache/security headers, CSRF rejection, and test-RP error handling.
5. A `finally` block terminates both process groups and deletes the temporary
   persistence root.

The scanner accepts only exact loopback HTTP origins by default. It never follows
redirects and sends no cookies, bearer tokens, client secrets, OAuth codes,
Passkey data, or user credentials. It does not test real Google/Passkey login,
consent, authenticated admin mutations, rate exhaustion, destructive behavior,
or load.

## Isolated Preview

The `Isolated Preview DAST` workflow is `workflow_dispatch` only and uses the
GitHub environment named `isolated-preview`. Before an owner runs it, protect
that environment with the repository's required-reviewer policy and configure
these environment variables:

| Variable | Required value |
| --- | --- |
| `PGID_DAST_PREVIEW_ORIGIN` | Exact isolated origin matching `https://pg72-id-preview.<preview-account-subdomain>.workers.dev` |
| `PGID_DAST_PREVIEW_OPT_IN` | `owner-approved-isolated-preview` |

The origin is both the target and the exact allowlist value. The scanner rejects
`https://sso.pg72.tw`, every custom domain, a different Worker name, non-HTTPS,
non-default ports, credentials, paths, and arbitrary user input before network
access. Preview must use a separate Cloudflare account, D1, secrets, queues,
rate-limit namespaces, and synthetic identities. No Preview run was performed by
the change that introduced this workflow.

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
