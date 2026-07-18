# PGID

PGID is the custom identity provider for PG72 services. Phase 0 runs on Cloudflare Workers and D1 and provides:

- Google sign-in and Passkey authentication;
- optional Discord, GitHub, Facebook, Apple, and Telegram sign-in that remains hidden unless its credentials are configured;
- OAuth 2.1 / OpenID Connect Authorization Code with PKCE S256, EdDSA ID tokens, and a published JWKS;
- nonempty central `sid` claims on every user ID token, with refresh issuance bound to the same live user session;
- admin/developer-managed OAuth clients (dynamic registration disabled), mandatory consent, and the `bootadmin`/`admin`/`developer`/`user` platform role model;
- host-only central sessions, device revocation, invitations, account suspension, and audit events;
- an ordered local D1 migration ledger from `0001` through head `0024`: `0013`-`0019` add the confidential-client, Passkey step-up, identity-ownership, registration, restricted-account, global-logout, and recovery contracts; `0020`-`0022` add the schema-only observability and evaluator-proof foundations; `0021`, `0023`, and `0024` add the archive ledger, R2 evidence contract, and forward evidence guard. `0024` preserves existing immutable legacy receipts while rejecting new terminal R2-version evidence without an observed byte count. The last recorded production state was applied through `0012`; an authorized operator must reverify the live ledger before relying on that historical record;
- a local durable global-logout path: actual `(sid, client)` visits, atomic D1 revoke/audit/outbox writes, a dedicated Queue/DLQ, bounded retry/Cron recovery, redacted operator replay, and an idempotent test-RP receiver; migration, queue provisioning, production RP receivers, external alerts, and rollout evidence remain incomplete;
- a local archive source boundary with an unwired create-only R2 writer and a pure non-HTTP one-object restore verifier. The verifier checks an externally supplied expected manifest, object identity, metadata, size, and stored/computed digests before returning detached records. Authenticated independently retained manifest provenance, KEK custody, runtime R2 integration, a restore sink/exercise, external backup/retention, and remote proof remain absent; observability remains `source_present_unverified` and `encrypted_r2_archive` remains `dependency_missing`;
- a tightly scoped mail introspection path for Dovecot: local source authorizes only `pgid-mail-introspect` to inspect eligible `pg72-webmail` access tokens and disclose verified email; the last production record did not include deployment or provisioning of this path, and live state must be reverified;
- Passkey step-up before every OAuth client mutation, using a one-time session/user-bound challenge, required user verification, and a D1 session timestamp; this path is implemented and tested locally, while the last production record did not include its migration/deployment, independent review, or smoke test, and the current live state must be reverified;
- a local, default-disabled recovery path: ten one-use 160-bit `PGID-R1` codes, hash-only storage, an isolated ten-minute recovery session, required-UV Passkey replacement, atomic code rotation, and central session/token revocation; the last production record did not include `0019`, enabled `RECOVERY_MODE`, or a recovery drill, and an authorized operator must reverify live state before rollout;
- an independent OIDC relying party based on `oauth4webapi`;
- workerd regression tests for discovery, security headers, registration policy, request aborts, D1 constraints, PKCE transactions, and callback replay.

The canonical architecture and migration decisions are in [`codex.md`](./codex.md). Existing deployment records describe PGID at `https://sso.pg72.tw` as an invite-only beta and show Copy and Link using it for production sign-in; those records must be reverified and are not full Production GO. Public registration, global-logout Preview/production rollout and RP receivers, external alerting, recovery-code Preview/production rollout and drills, and other security gates remain incomplete.

## Documentation

| Document | Purpose |
| --- | --- |
| [`codex.md`](./codex.md) | Canonical architecture and security baseline (single source of truth). |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Local contribution workflow, verification gate, and documentation sync rules. |
| [`SECURITY.md`](./SECURITY.md) | Release gate and the accepted Phase 0 finding. |
| [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md) | License provenance for Better Auth, Inter, VitePress, and other distributed third-party components. |
| [`docs/about-PGID.md`](./docs/about-PGID.md) | Product introduction; what PGID is and why. Also used by the frontend `/about` page. |
| [`docs/api/PGID-integration.md`](./docs/api/PGID-integration.md) | Concise integration reference: endpoints, scopes, claims, token lifetimes, client auth, and copyable `oauth4webapi`/generic examples. |
| [`docs/runbooks/public-registration-abuse.md`](./docs/runbooks/public-registration-abuse.md) | Local public-registration abuse thresholds, triage, account containment, false-positive handling, and rollback. |
| [`docs/runbooks/global-logout.md`](./docs/runbooks/global-logout.md) | Global-logout migration checks, Preview acceptance, delivery triage/replay, failure drills, and rollback. |
| [`docs/runbooks/account-recovery.md`](./docs/runbooks/account-recovery.md) | Recovery migration checks, isolated Preview acceptance, incident triage, enablement, and rollback. |
| [`docs/runbooks/release-security.md`](./docs/runbooks/release-security.md) | Reproducible source, advisory, dry-run artifact, inventory, and safe DAST release gates. |
| [`wiki/`](./wiki/SUMMARY.md) | GitBook-compatible tutorial site (content source for `wiki.sso.pg72.tw`): user guides and developer walkthroughs. |

## Registration Policy

The committed production-target `REGISTRATION_MODE` in
`apps/sso/wrangler.jsonc` is `"invite"`. That source configuration is not proof
of the mode currently deployed; an authorized operator must verify live Worker
configuration. The code supports and tests both modes, but the switch to
`"public"` requires the `codex.md` §9.2 gate, explicit owner approval, and a
production deployment. Invitations stay fully functional in either mode; a
pending invitation still assigns its role (for example `admin`) and is consumed
on first sign-in.

Current safeguards in public mode:

- A first Google sign-in creates the account only when Google asserts a verified email; unverified emails are rejected in both modes.
- Telegram does not provide an email, so it never creates a PGID account in either mode. It can sign in only after that Telegram identity was explicitly linked from a standard authenticated PGID session; an existing link remains usable if the account is later restricted.
- Passkey registration still requires an existing account and an authenticated session.
- Public account creation is Google-only and requires an explicit current Terms/Privacy acceptance plus a Turnstile token that the Worker verifies server-side for the exact PGID hostname and registration action. A successful challenge creates a short-lived, one-time opaque intent whose raw value is returned once and stored only as a SHA-256 digest. The registration start exchanges it for an independent reference bound to Better Auth's actual OAuth state; only that reference crosses protected OAuth state. Existing linked providers remain usable for ordinary login, but a restricted account cannot add optional providers.
- D1 records the accepted Terms/Privacy version identifiers and server-side intent issuance time with the new user. Database triggers require the three acceptance fields together, preserve the initial values, and write an acceptance-history row in the user transaction. Direct history UPDATE/DELETE is rejected while the account exists; deleting the parent account removes its account-scoped history through the declared privacy-policy cascade.
- New-account creation has its own per-IP Workers Rate Limiting budget (`REGISTRATION_RATE_LIMITER`, 5/min), stricter than the sign-in limiter (30/min). The budget is consumed before any denial audit write or invitation lookup so those cannot be spammed.
- A public-created account is persisted as `restricted`; invited, bootstrap, and migration-backfilled existing accounts are `standard`. Restricted users retain ordinary login, account management, Passkey, consent, and OIDC, but cannot link another provider, hold an elevated PGID platform role, create or take ownership of OAuth clients, or use developer/admin/system-client management. Request guards re-read D1; every management/developer mutation also revalidates the actor's live session and active, standard, permission-relevant snapshot in the committing D1 batch, while migration `0017` enforces the role, provider-link, and client-owner boundaries. Restriction does not silently disable an already owned RP; an operator handles that client separately if incident evidence requires it.
- Administrators can filter by access level and explicitly restrict, promote, suspend, or reactivate within the role hierarchy. Restriction demotes to `user` and revokes central sessions/tokens; promotion does not reactivate the account or restore an old role. State mutation and the success audit commit together in D1.
- Suspended accounts and deleted (missing) users are blocked at session creation, so public mode does not bypass suspension. A deleted user who re-registers receives a brand-new `sub`.
- Registration denials never reveal whether an account exists.

Known-incomplete gates that block opening registration (tracked in `codex.md`
§9.2) include production deployment/configuration and independent review of the
local Turnstile/legal-acceptance and restricted-account slices, owner approval
of the live policy version identifiers, Preview validation of the documented
abuse thresholds plus an assigned operator and external alert delivery, OIDC
conformance/security testing, authenticated isolated-Preview DAST, load testing,
backup-restore and key-rotation drills, full back-channel logout rollout, and
the default-disabled recovery path's Preview/rollback drills. Automated SAST,
secret, dependency, workflow/Wrangler config, artifact, and localhost
public-surface DAST gates now exist, but they do not prove those operational
gates. The local implementations and runbooks do not claim production delivery
or operational monitoring exists.

## Workspace

```text
apps/sso       PGID Worker, React account center, D1 migrations
apps/test-rp   Independent OIDC protocol relying party
wiki           PGID Wiki source and VitePress static site
```

The Wiki keeps `wiki/README.md`, `wiki/SUMMARY.md`, and `.gitbook.yaml` as its
GitBook-compatible content source. Run it locally with `pnpm dev:wiki`.

Cloudflare Pages settings:

| Setting | Value |
| --- | --- |
| Root directory | `/` (repository root) |
| Build command | `pnpm --filter @pg72/wiki check` |
| Build output directory | `wiki/.vitepress/dist` |
| Environment variable | `NODE_VERSION=24` (also pinned by `.node-version`) |
| Environment variable | `PNPM_VERSION=11.5.0` |
| Functions and bindings | None; deploy the static output only. |

## Relying Parties

PG72 services integrate as standard OIDC relying parties. Integration status and
the remaining gates are tracked in `codex.md` §18:

| Service | Integration | Status |
| --- | --- | --- |
| Copy (`copy.pg72.tw`) | Native OIDC confidential client + PKCE, guest-code path kept separate | Last recorded as production live; current traffic and configuration require authorized re-verification. Guest six-digit code retained. |
| Link (`link.pg72.tw`) | `oauth4webapi` BFF, stable `sub` session | Last recorded as production live; current traffic and configuration require authorized re-verification. PGID delivery is local-only; Link receiver/rollout remains pending. |
| Status (`status.pg72.tw`) | OIDC BFF + D1 opaque session | Local-source login integration complete; no current Preview or receiver state is asserted without authorized live re-verification. |
| Upload admin (`upload.pg72.tw/admin`) | Authlib OIDC + SQLite session (`client_secret_post`) | Local-source integration complete; no current Preview or cutover state is asserted without authorized live re-verification. |
| File Browser (`file.pg72.tw`) | oauth2-proxy gateway + proxy auth header | Source plan only; no deployment state is asserted without authorized live re-verification. |
| Roundcube (`webmail.pg72.tw`) | Native Generic OIDC + Dovecot XOAUTH2 for mail | PGID prerequisite implemented locally; no deployment, service-client provisioning, or mail-cutover state is asserted without authorized live re-verification. |

Existing records show Copy and Link switched production traffic to PGID; live
state must be reverified. Relying parties must use
`client_secret_post` for the token endpoint (the provider's HTTP Basic parsing is
not RFC-6749-percent-decode compatible).

## Requirements

- Node.js 24 or newer
- pnpm 11.5.0
- Cloudflare account for remote resources
- Google OAuth Web client for real sign-in

All dependency versions are exact-pinned in the workspace lockfile. Better Auth core and plugins must remain on the same patch line.

## Local Setup

Install and initialize both local D1 databases:

```bash
pnpm install --frozen-lockfile
pnpm --filter @pg72/id cf-typegen
pnpm --filter @pg72/test-rp cf-typegen
pnpm --filter @pg72/id db:migrate:local
pnpm --filter @pg72/test-rp db:migrate:local
pnpm --filter @pg72/id db:seed-test-rp:local
```

Copy tracked `apps/sso/.dev.vars.example` to ignored `apps/sso/.dev.vars`, then replace the required placeholders with a random local secret and development Google credentials. The template exercises public mode, so it also needs a hostname-scoped Turnstile test widget and approved local Terms/Privacy version identifiers; set `REGISTRATION_MODE=invite` instead when that flow is not under test. Recovery remains independently controlled by `RECOVERY_MODE` and defaults to `disabled`; enable it only in a disposable local or isolated Preview environment prepared through migration `0019`. Optional provider values are intentionally empty so copying the template cannot enable a provider; only fill them in when testing that provider. Never commit the real `.dev.vars`.

```bash
openssl rand -base64 32
```

Google OAuth must allow this local callback exactly:

```text
http://localhost:5173/callback/google
```

Start the services in separate terminals:

```bash
pnpm dev
pnpm dev:rp
```

- PGID: `http://localhost:5173`
- OIDC test RP: `http://localhost:5174`

The local test RP is a public client. It has no client secret; its transaction state, nonce, and PKCE verifier are stored in its D1 database, and its browser receives only an HttpOnly transaction cookie.

## Verification

```bash
pnpm check
pnpm security:tools:install
pnpm security:check
pnpm dast:local
```

`pnpm check` is the canonical repository gate. It runs the clean-build-output
regression and workspace package checks, covering type checks, workerd and
relying-party protocol tests, Wiki route/link/header validation, and production
and static builds.

`pnpm security:check` runs type-aware Promise analysis over both Workers,
required checksum-pinned Gitleaks history scanning, a redacted bounded scanner
over tracked/untracked files and ignored sensitive filenames, captured
Secretlint, recursive workflow/package-script allowlists with exact
workflow/job/step environment scopes, exact source/generated Wrangler binding
targets, the dependency advisory policy, a production
`wrangler deploy --dry-run --outdir` artifact gate, a path-free
dependency/license inventory, and negative tests for the automation itself.
JavaScript and TypeScript assignments are parsed with the pinned TypeScript
compiler AST and a bounded static evaluator for literals, static templates,
parentheses, and string concatenation. The line-oriented dotenv/config parser
separately supports `export`, `const`, `let`, and `var`; bounded UTF-8,
UTF-16LE/BE, and NUL-interleaved representations share the same token,
private-key, assignment, and high-entropy families. Source fixtures and
generated enum/metadata exceptions require an exact raw path, normalized key,
and complete value. Better Auth's generated fallback additionally requires all
three exact literal digests, literal forms, and AST contexts; marker substrings
do not waive a finding. Immediately after checkout, both workflows run a
dependency-free Node standard-library identity check before authorization,
package-manager setup/install, or any other repository script. It pins the
exact workflow file set/raw LF bytes, all four manifest/script-map identities,
the complete `pnpm-workspace.yaml` lifecycle/build policy, the frozen lockfile,
and the exact `patches/` file set and raw digests. It also requires both pnpm
workspace hook filenames, project `.npmrc`, `binding.gyp`, and pre-existing
`node_modules` paths to be absent at every code-owned package root. The later
gate rechecks those workflow bytes before YAML/structural validation and
separately pins both every complete workspace `scripts` object and the
recursively reachable graph. It models implicit `pre*`/`post*` hooks plus
`preinstall`/`install`/`postinstall`/`prepare` across root and filtered
workspaces; policy cannot extend any contract. The upload step is fixed to
`.artifacts/release` with error-on-missing, hidden-file
exclusion, and seven-day retention. Workflow environment policy can select only
code-owned `DAST_*`, `CI`, and `NO_COLOR` values; `CLOUDFLARE_*`, legacy `CF_*`,
and `WRANGLER_*` remain hard-denied even if policy and workflow are changed
together. The deterministic production Wrangler `index.js` is also pinned by a
code-owned whole-file SHA-256 before the structural artifact and AST secret
scanners run. Runtime, dependency, bundler, or build-chain changes therefore
require human review and two matching clean build/dry-run outputs before that
digest is deliberately updated; the gate never learns a new digest from policy
or its current output. Current matching evidence is local to the measured
toolchain; Linux entry-digest equality remains unverified, not disproven.
Diagnostics normalize
safe relative paths and replace sensitive, secret-bearing, absolute/outside, or
terminal-unsafe paths with a short SHA-256 identifier. The audit covers runtime,
build, and development dependencies so tooling advisories cannot bypass the
gate.

The audit currently reports the accepted Moderate `GHSA-p2fr-6hmx-4528`.
[`security/accepted-advisories.json`](./security/accepted-advisories.json)
records its exact package/version, rationale, controls, owner, expiry, and
review command. The gate fails if the advisory changes, disappears while its
waiver remains, expires, or is joined by any unrecorded finding. High and
Critical advisories cannot be waived by this file.

`pnpm dast:local` creates fresh temporary local D1 state, starts ephemeral PGID
and test-RP Workers only at literal `127.0.0.1:5173`/`:5174`, and runs
credential-free public/error probes without following redirects or permitting
Host overrides. It terminates both process groups and deletes the synthetic
state afterward.

The protected manual Preview path and its limitations are documented in the
[release-security runbook](./docs/runbooks/release-security.md); it has not been
run by this source change.

These commands verify local source only. They do not deploy, migrate remote D1,
provision clients, exercise authenticated Preview/production flows, or provide
a production smoke-test record.

## Cloudflare Provisioning

### Preview

Preview environments must live in a separate Cloudflare account with separate D1
databases, queues, secrets, domains, Google callbacks, and Rate Limiting
namespaces. A branch deployment must never bind Preview code to production data
or secrets. The local test RP remains available for protocol regression coverage.

- OAuth clients cannot skip consent. Each account must approve a new client or newly requested scope before authorization continues.
- The account center lists approved applications and can revoke their consent, pending authorization codes, access tokens, and refresh tokens.
- Self-service account deletion requires a fresh session. The bootstrap administrator is protected; other `user` and `admin` accounts may delete themselves.

Consent revocation prevents future token use and requires the application to request consent again. It does not yet terminate an application's own local session cookie; back-channel logout or RP-side session validation remains required for immediate cross-site logout.

Preview secrets must be created only in the isolated Preview account and must
never be stored in source control.

### Production

Existing records describe a `pg72-id` Worker with a production identity D1,
queues/secrets, the exact `sso.pg72.tw` custom domain, and production
issuer/Passkey settings.
The last recorded production state reports migrations through `0012`; an
authorized operator must reverify current remote state before a maintenance
operation. Deployment history is not evidence that the full gate below has
passed.

The committed `database_id` is a local-development placeholder. Configure the
reviewed production binding through the deployment environment before any remote
operation; never treat the placeholder as a production resource.

Full Production GO checklist:

1. An authorized operator verifies production queues, secrets, exact bindings, custom domain, and migrations for the release.
2. An authorized operator verifies that the target identity database is production-only and that the retired Preview Worker, domain, queues, and Preview OAuth grants remain absent; historical cleanup records do not establish current state.
3. Do not run the local test client seed against production. An authorized operator verifies that no remote test client or grants remain before the release.
4. Create production OAuth clients through an authenticated admin operation with exact HTTPS redirect URIs.
5. Configure Google callback `https://sso.pg72.tw/callback/google`.
6. Re-run real Google and production Passkey flows, verify Copy/Link sign-out, and complete the `0018`/dedicated Queue/DLQ rollout, each RP receiver, multi-RP/failure/rollback drills, external alerts, the `0019` recovery-code rollout and lost-device drill, signing-key rotation, restore, and independent-review gates before changing the beta status.

Mail Path A remains a separate owner-run rollout:

1. Review the locally implemented Passkey step-up and verify its session/challenge binding, UV, replay, expiry, and missing-Passkey behavior independently; the last recorded production state lacked migration `0014` and this Worker version, so reverify before rollout.
2. Verify the exact production `pg72-webmail` client metadata and take a private production D1 backup.
3. Run the provider-identity and Passkey credential duplicate preflights in `codex.md` §§0.1-0.2 and review pending migrations in numeric order (`0013` through `0024`) in isolated Preview. Provision the dedicated logout Queue/DLQ and deploy only verified Worker source with `PASSKEY_STEP_UP_MAX_AGE_SECONDS=600` plus Rate Limiting namespaces `1004`, `1005`, and `1006` bound as configured. Migrations `0016`-`0019` are required by the current Worker schema even while the committed production target remains invite-only and recovery-disabled; `0020`-`0024` remain unwired observability/archive foundations and do not enable alerts or archival. Applying any migration does not authorize changing `REGISTRATION_MODE`, changing `RECOVERY_MODE`, or enabling an RP receiver/provider.
4. After Passkey step-up, use a same-origin PGID admin session less than 10 minutes old to provision `pgid-mail-introspect`; immediately store its one-time secret in the approved secret store, never source, logs, issues, or chat.
5. Verify eligible active, ineligible inactive, and bad-credential `401` production behavior. Verify rate-limit `429` and limiter-failure `503` only in isolated Preview or a controlled local test, never by flooding or breaking production.
6. Cut over Dovecot/Roundcube only in an owner-controlled maintenance window with
   an independently reviewed rollback plan ready.

Dynamic client registration, passwords, Email OTP, TOTP, cross-subdomain cookies, and Cloudflare Access authentication are intentionally disabled.

## License

PGID's original source code is licensed under the
[Apache License 2.0](./LICENSE). See [`NOTICE`](./NOTICE) for attribution and
[`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md) for components that retain
their own licenses.
