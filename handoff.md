# PGID Engineering Handoff

> Snapshot: 2026-07-15 21:17 CST (Asia/Taipei, UTC+08:00)  
> Production issuer: `https://sso.pg72.tw`  
> Production Worker: `pg72-id`  
> Active Worker version at handoff: `eafd3330-9299-44f6-baa5-df57bfa41ad6`  
> Status: friends/invite beta; do not enable public registration yet

This file is the operational handoff for the PGID SSO project. It records the
state that was verified on 2026-07-15, the decisions that must not be silently
changed, the safe deployment/rollback procedure, and the next integration work.
It intentionally contains no secret values, OAuth tokens, session cookies,
private keys, Google client IDs, Cloudflare API tokens, or personal data.

The architecture baseline remains in `codex.md`. `handoff.md` is the current
execution state and runbook; `codex.md` is the longer-term contract and security
design. When the two disagree, stop and reconcile them before deploying.

## 1. Executive Summary

PGID is a first-party OAuth 2.1/OpenID Connect identity provider running on
Cloudflare Workers and D1. Authentication currently supports Google and Passkey.
The account center supports sessions, OAuth consent revocation, invitations,
account deletion, audit display, and Passkey management.

The production SSO Worker is live at `https://sso.pg72.tw`. The deployment at
this handoff passed:

- strict TypeScript;
- 27/27 workerd SSO regression tests;
- production Worker and React builds;
- build artifact scan confirming no `.dev.vars*` file remains;
- Wrangler startup profiling (40 ms reported during final deployment);
- health, D1 readiness, session, discovery, and JWKS HTTP smoke tests;
- unauthenticated Passkey endpoint negative tests;
- security-header checks;
- edge propagation checks against both current Cloudflare IPv4 addresses;
- `https://copy.pg72.tw` availability check.

The final deployed Passkey management UI can:

- list all Passkeys owned by the authenticated user;
- display whether each credential is device-bound or multi-device and whether
  it reports backup/sync state;
- rename a Passkey inline, with a 64-character UI and Worker limit;
- delete a Passkey through an accessible confirmation dialog;
- require a session created within the last 10 minutes before deleting the
  user's final Passkey;
- reject cross-account Passkey mutation and cross-origin requests;
- write `passkey.renamed`, `passkey.deleted`, and denied final-deletion audit
  events.

Important: Copy production has not yet switched to PGID. The Copy source has
the PGID implementation, but the current central SSO database has zero OAuth
clients and the current Pages production environment still exposes only the old
Google/NextAuth binding names. The completed end-to-end Copy validation was in
Preview, and that Preview was intentionally retired. Do not claim production
Copy SSO is complete until the cutover procedure in this document passes.

## 2. Non-Negotiable Product Decisions

The following requirements came directly from the owner and must be preserved:

- The system begins as friends/invite-only and may later open to anyone.
- The primary platform is Cloudflare Workers/D1; use a VPS only where the
  workload or upstream service genuinely requires it.
- Daily user authentication is Google plus Passkey.
- This is a custom SSO system. Do not replace it with Cloudflare Access.
- New OAuth clients must always show a PGID consent screen. No first-party
  client may silently skip initial/new-scope consent.
- Users must be able to view and revoke previously authorized applications.
- Users may delete their own accounts after fresh authentication.
- The bootstrap administrator is the recovery owner and cannot self-delete.
- Other `user` and `admin` accounts may self-delete.
- Copy's six-digit guest code is intentional and must not be removed. Guest-code
  users remain separate from PGID users and must never be merged by email.
- Preview and production must use separate Cloudflare accounts/resources. Never
  bind a Preview deployment to a production D1 database.
- File Browser and Roundcube sources are upstream reference snapshots. Production
  packages must be built from a pinned stable upstream release and checksum/image
  digest, not deployed directly from the supplied source snapshot.

## 3. Current Production Inventory

### 3.1 SSO Worker

| Item | Current value |
| --- | --- |
| Worker | `pg72-id` |
| Issuer/custom domain | `https://sso.pg72.tw` |
| Active version | `eafd3330-9299-44f6-baa5-df57bfa41ad6` |
| Deployment ID | `71c6d61f-8a45-4d01-90ec-f2cc42391423` |
| Compatibility date | `2026-07-15` |
| Compatibility flags | `nodejs_compat` |
| Registration mode | `invite` |
| Passkey RP ID | `sso.pg72.tw` |
| Passkey origin | `https://sso.pg72.tw` |
| Observability | Workers logs/traces enabled |
| Assets | Worker Static Assets, SPA fallback, Worker first |

The final deployment reported a 40 ms startup time. Treat this as a local/edge
deployment signal, not a latency SLO.

### 3.2 Production D1

The binding is `PG72_ID_DB`. Its database name is still
`pg72-id-preview`, because the isolated Preview database was promoted in place.
Despite its historical name, this is the live production identity database.

**Never delete `pg72-id-preview` based on its name.** Rename it only through a
separately planned maintenance operation after confirming Wrangler/Cloudflare
support and updating every source-of-truth binding.

Snapshot at handoff:

| Metric | Value |
| --- | ---: |
| Database size | 278,528 bytes |
| Tables | 16 |
| Users | 1 |
| Linked accounts | 1 |
| Passkeys | 2 |
| Active sessions | 1 |
| OAuth clients | 0 |
| OAuth consents | 0 |
| Audit events | 3 |

This is not close to D1 capacity. The 2026-07-15 login failure was not a quota
problem; see the incident section.

All five D1 migrations are applied remotely. `wrangler d1 migrations list`
reported no pending migration at handoff.

### 3.3 Production Queues

| Queue | Role |
| --- | --- |
| `pg72-id-security-events` | security/audit delivery queue; one producer and one consumer |
| `pg72-id-security-events-dlq` | dead-letter queue; alerting/dashboard still pending |

The Worker is both producer and consumer for the primary queue. Queue delivery
currently records idempotent delivery in `security_event_delivery`.

### 3.4 Production Secret Names

The Worker has exactly these secret bindings:

- `BETTER_AUTH_SECRET`
- `BOOTSTRAP_ADMIN_EMAIL`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`

Only the names belong in documentation. Values must remain in Wrangler/Cloudflare
secret storage. Never put them in source control, shell history, issue text,
screenshots, logs, `handoff.md`, or chat.

`BETTER_AUTH_SECRET` encrypts sensitive Better Auth state, including the JWKS
private key stored in D1. Rotating it without a coordinated data/key procedure
can make the live JWKS row undecryptable and break all sessions.

### 3.5 Cloudflare Account D1 List

There were eight D1 databases at handoff:

- `cloud-clipboard`
- `link-short-db`
- `night-study-db`
- `nightstudy`
- `ns-db`
- `pg72-id-preview` (live production PGID database)
- `study-city-db`
- `xugou_db`

The former `cloud-clipboard-sso-preview`, test RP D1, and unused Arcant D1 were
exported and deleted.

### 3.6 Copy Pages Project

| Item | Current value |
| --- | --- |
| Project | `cloud-clipboard` |
| Production branch | `master` |
| Canonical production deployment | `2caf74f0-0807-4f52-82e4-98ec01ad2d3d` |
| Production deployment enabled | yes |
| Automatic Preview deployments | disabled (`none`) |
| Production D1 binding | `DB` -> `cloud-clipboard` |
| Preview D1 bindings | none |
| Preview env bindings | none |
| Preview deployments | none at cleanup verification |

Production Copy binding names at handoff are `DB`, `GOOGLE_CLIENT_ID`,
`GOOGLE_CLIENT_SECRET`, and `NEXTAUTH_SECRET`. This confirms production Copy is
still on the old Google configuration. The planned PG72 variables are not yet
configured in production.

## 4. Repository and Workspace Layout

The workspace root is `/Users/pgpenguin72/sso.pg72.tw`.

```text
sso.pg72.tw/
├── README.md                  local setup and deployment summary
├── SECURITY.md                release gate and accepted finding
├── codex.md                   canonical architecture baseline
├── handoff.md                 this current-state/runbook document
├── package.json               pnpm workspace scripts
├── pnpm-lock.yaml             exact dependency resolution
├── pnpm-workspace.yaml
├── apps/
│   ├── sso/                   PGID Worker + React account center
│   │   ├── src/               browser UI
│   │   ├── worker/            Hono edge entrypoint, auth, audit, config
│   │   ├── migrations/        production D1 migrations
│   │   ├── seed/              local test RP client only
│   │   ├── test/              workerd regression suite
│   │   └── wrangler.jsonc     production source of truth
│   └── test-rp/               localhost-only OIDC relying-party harness
└── 原專案代碼/
    ├── copy.pg72.tw/
    ├── link.pg72.tw/
    ├── status.pg72.tw/
    ├── upload.pg72.tw/
    ├── file.pg72.tw/
    └── webmail.pg72.tw/
```

Critical version-control note: the workspace root is not currently a Git
repository. Several service directories under `原專案代碼/` are independent Git
repositories with existing dirty worktrees. At the handoff snapshot:

- Copy: dirty, many SSO integration changes;
- Link: dirty, local SSO integration changes;
- Status: dirty, local SSO/security changes;
- Upload: dirty, local SSO/security changes;
- File Browser: clean upstream snapshot;
- Webmail: clean upstream snapshot.

Do not use `git reset --hard`, `git checkout --`, or bulk cleanup commands. The
dirty changes are the project work and/or owner work. Establish a private Git
repository and review/commit each service deliberately before further production
rollout. The lack of version control/CI for the SSO root is a top operational
risk.

## 5. Technology Baseline

### SSO

- Node.js: 24 or newer
- Package manager: pnpm 11.5.0
- Cloudflare Wrangler: 4.110.0 in the project
- TypeScript: 7.0.2
- Vite: 8.1.4
- React/React DOM: 19.2.7
- Hono: 4.12.30
- Better Auth: 1.6.23 exact pin
- `@better-auth/passkey`: 1.6.23 exact pin
- `@better-auth/oauth-provider`: 1.6.23 exact pin
- Workers Vitest pool: 0.18.4

Core and all Better Auth plugins must remain on the same audited patch line.
Do not upgrade one package independently. Do not move the auth core to beta/RC
without a separate GO/NO-GO review.

### Copy

Copy uses Next.js 15.5.20 and NextAuth 5 beta. Its SSO changes introduce PGID
OIDC, a D1-encrypted server-side token vault, refresh-token leasing/CAS, and a
separate guest-code identity path. The code exists locally but production has not
been cut over.

## 6. SSO Runtime Architecture

### 6.1 Request Path

`apps/sso/worker/index.ts` is the Worker entrypoint. It provides:

- Hono middleware for security headers, request IDs, structured request logs,
  cache policy, body limits, and exact-Origin checks;
- `/health` and `/ready`;
- account audit and authorized-application APIs;
- invitation and user status admin APIs;
- controlled Passkey update/delete routes;
- Better Auth routing for sessions, Google, Passkey, OAuth/OIDC, discovery,
  JWKS, token, introspection, revoke, consent, and logout;
- SPA asset fallback;
- Queue consumption for security events.

`createAuth(env, executionCtx)` is request-scoped. Do not turn it into a mutable
module-level singleton: D1 and request I/O are request-bound in Workers.

### 6.2 Google Login

- Better Auth social provider: Google.
- Google token-based sign-in shortcut is disabled; the provider performs the
  expected remote flow.
- Google prompts account selection.
- Registration is `invite` unless the normalized email exactly matches
  `BOOTSTRAP_ADMIN_EMAIL`.
- Implicit account linking is disabled.
- Different-email linking is disabled.
- Unlinking every account is disabled.
- OAuth provider tokens are encrypted by Better Auth when stored.

The Google callback is:

```text
https://sso.pg72.tw/callback/google
```

### 6.3 Passkey

- RP ID: `sso.pg72.tw`
- expected origin: `https://sso.pg72.tw`
- resident key: preferred
- user verification: required
- credentials may be platform, hardware, or synchronized multi-device Passkeys

Passkey endpoints used by the UI:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/passkey/list-user-passkeys` | list the current user's Passkeys |
| POST | `/passkey/generate-register-options` / Better Auth registration paths | start registration |
| POST | `/passkey/verify-registration` | finish registration |
| POST | `/passkey/update-passkey` | rename an owned Passkey |
| POST | `/passkey/delete-passkey` | delete an owned Passkey |

Rename/delete use the same Better Auth client paths so its reactive Passkey list
refresh still works. The Worker intercepts only update/delete to add project
policy:

- exact production Origin on unsafe requests;
- 4 KiB body limit;
- active authenticated session;
- account rate limit;
- UUID/name validation;
- ownership enforced in the D1 mutation predicate;
- not-found response instead of revealing another user's credential;
- 64-character name limit;
- final-Passkey deletion requires a session younger than 10 minutes;
- success/denied audit events.

The account currently has two Passkey rows. One may be a credential created under
the former Preview RP ID and therefore unable to authenticate at `sso.pg72.tw`.
The owner should identify it by testing the valid production Passkey before
deleting the obsolete row. Never delete both recovery paths accidentally.

The final-Passkey dialog error instructs the user to sign out and sign in again
when fresh authentication is required.

### 6.4 OAuth/OIDC Provider

- Authorization Code flow only for browser users.
- PKCE S256 required for first-party web/public clients.
- Dynamic client registration disabled.
- Client consent cannot be skipped; D1 triggers enforce `skipConsent = 0`.
- Scopes: `openid`, `profile`, `email`, `offline_access`.
- Access token lifetime: 15 minutes.
- ID token lifetime: 10 minutes.
- Refresh token lifetime: 30 days.
- Authorization code lifetime: 60 seconds.
- JWT issuer: `https://sso.pg72.tw`.
- Current JWT audience: `https://api.pg72.tw`.
- Custom role claim: `https://pg72.tw/role`.
- Opaque access/refresh/client-secret prefixes are explicit.
- OAuth `resource` indicators are rejected at the Worker boundary due the
  accepted Better Auth issue described in `SECURITY.md`.

At handoff there are zero production OAuth clients. OIDC protocol infrastructure
is live, but no production relying party can complete authorization until a
client is created.

### 6.5 Session Model

- SSO sessions are D1-backed and use host-only cookies.
- Cookie prefix: `pg72_id`.
- Cookies are `Secure`, `HttpOnly`, `SameSite=Lax`, path `/` in production.
- Cookie cache is disabled.
- Session expiry: 30 days.
- Fresh session age: 10 minutes.
- Session update age: 1 day.
- Suspended users cannot create new sessions.

An RP's local session is separate from the SSO session. Revoking the central
session or consent does not automatically remove every application's cookie.
The `sid` + back-channel logout contract remains a required Phase 2 task.

## 7. Account Center Features

The React account center currently includes:

- system/light/dark theme with local user preference override;
- Google and Passkey sign-in;
- OAuth consent screen with application metadata and scope explanation;
- account ID, role/status, email and profile display;
- authorized application list and consent/token revocation;
- Passkey list, registration, rename, deletion and metadata;
- active device/session list;
- revoke one session and revoke other sessions;
- personal audit activity;
- admin invitation creation;
- bootstrap-protected self-service account deletion.

The penguin emoji is the current temporary brand mark.

Known account-center gaps:

- no recovery-code implementation yet;
- no complete admin user search/list UI;
- no OAuth client creation/rotation UI;
- no signing-key status/rotation UI;
- no Queue/DLQ dashboard;
- no central/global logout delivery status;
- Passkey registration and authentication are not yet fully represented in the
  custom audit table; rename/delete are audited by the current Worker routes.

## 8. D1 Schema and Migration History

### `0001_better_auth.sql`

Creates Better Auth and OAuth provider tables:

- `user`
- `session`
- `account`
- `verification`
- `jwks`
- `passkey`
- `oauthClient`
- `oauthRefreshToken`
- `oauthAccessToken`
- `oauthConsent`
- `rateLimit`

It also creates foreign keys and lookup indexes. User deletion cascades through
sessions, linked accounts, Passkeys, and most OAuth grants.

### `0002_pg72_identity.sql`

Adds PG72-specific state:

- `invitation`
- `audit_event`
- `security_event_delivery`
- `logout_delivery`
- user role/status guard triggers

### `0003_require_oauth_consent.sql`

Normalizes existing clients to require consent and creates insert/update triggers
that reject `skipConsent != 0`.

### `0004_unique_oauth_consent.sql`

Removes duplicate consent rows and creates partial unique indexes per
user/client/reference.

### `0005_copy_refresh_grant.sql`

Updates pre-existing `pg72-copy-preview` or `pg72-copy` clients to the exact
confidential-client/refresh-token contract only when a secret and expected exact
redirect URI already exist. It does not create a client. Because the current
database has zero clients, applying this migration alone cannot enable Copy.

## 9. Security Controls

### 9.1 Edge and Browser

- HTTPS-only production origin.
- HSTS with two-year max age and subdomains.
- CSP: self-only by default, no objects, no framing, explicit Google form action
  and Google profile image origin.
- `frame-ancestors 'none'` and `X-Frame-Options: DENY`.
- `X-Content-Type-Options: nosniff`.
- `Referrer-Policy: no-referrer`.
- Permissions Policy restricts WebAuthn create/get to self.
- Auth/API responses use `Cache-Control: no-store`; discovery/JWKS metadata has
  a short explicit cache policy.
- No wildcard credentialed CORS.
- Exact Origin for admin and Passkey management mutations.
- Bounded JSON/form bodies where applicable.

### 9.2 Identity and OAuth

- Invite-only registration.
- Protected bootstrap administrator.
- Explicit client consent with database triggers.
- Dynamic registration disabled.
- Exact redirect URIs; production must use HTTPS.
- PKCE, state, nonce, issuer/audience checks.
- Short authorization code and token lifetimes.
- Encrypted provider token storage.
- Host-only session cookies.
- Active/suspended account gate.
- D1 and Cloudflare Rate Limiting controls.
- No Cloudflare Access authentication dependency.

### 9.3 Accepted Finding

`GHSA-p2fr-6hmx-4528` affects `@better-auth/oauth-provider@1.6.23`.
It is recorded as Moderate because the stable line did not yet contain a fix at
the snapshot. Compensating controls:

- one fixed valid audience;
- reject every `resource` parameter at authorize/token;
- resource servers require exact audience and do not use RFC 8707 as an
  authorization boundary.

Upgrade core/plugins together to the first audited stable fixed release, run its
migrations and full protocol suite, then reassess the temporary edge rejection.

### 9.4 Security Work Still Required Before Public Registration

- independent security review and OIDC security/conformance testing;
- complete audit coverage for login, Passkey registration/authentication,
  session changes, client/key changes and admin queries;
- Turnstile/abuse controls;
- Terms/Privacy and retention implementation;
- recovery codes and break-glass drill;
- signing-key rotation drill;
- D1 backup restore drill;
- DLQ alerts and operator dashboard;
- back-channel logout and replay-safe logout token processing;
- dependency/secret/source-map checks in CI;
- no open Critical/High findings.

## 10. 2026-07-15 Login Incident

### Symptom

Google callback created/updated the Google account and a new session, but the
browser could not load the dashboard. `/get-session` returned HTTP 500.

### Root Cause

The promoted Preview D1 contained a JWKS private key encrypted with the Preview
`BETTER_AUTH_SECRET`. Production used a different secret. Better Auth could not
decrypt the private key and threw:

```text
BetterAuthError: Failed to decrypt private key.
```

This was not D1 capacity, DNS, migration, Google callback, or missing user data.
The D1 database was only about 278 KiB.

### Recovery Performed

1. Exported the D1 database to a private 0600 backup.
2. Removed the old Preview Worker/domain/queues so it could no longer write.
3. Removed Preview OAuth client/tokens/consent.
4. Cleared verification, sessions and rate-limit state.
5. Deleted the guarded obsolete JWKS row.
6. Regenerated production JWKS under the production secret.
7. Verified a production session through `/get-session`.
8. Retained user and linked Google account records.

### Prevention

- Never promote encrypted auth data between environments with different secrets
  without an explicit re-encryption/key-rotation plan.
- Never point two issuers at one D1 database.
- Back up before JWKS/session surgery.
- Verify callback plus `/get-session`, not callback alone.
- Keep Preview in a separate Cloudflare account.

## 11. Preview/Test Resource Retirement

The following temporary resources were retired after export:

- Worker/domain `pg72-id-preview` / `sso-preview.pg72.tw`;
- Preview security queue and DLQ;
- test RP Worker/domain/D1 (`sso-test.pg72.tw`);
- Copy Preview deployments;
- Copy Preview D1 `cloud-clipboard-sso-preview`;
- Copy Preview OAuth client, grants and tokens;
- unused Arcant `steep-art-cf42` Worker/domain/D1.

Cloud Clipboard automatic Preview deployment is set to `none`. Its Preview D1
and env bindings are empty. Production bindings were verified unchanged after
cleanup.

The local test RP remains and is explicitly localhost-only:

- issuer: `http://localhost:5173`
- RP base: `http://localhost:5174`
- no remote deploy or Preview migration script

Future Preview resources must use a separate Cloudflare account, separate D1,
queues, secrets, Google callback, rate-limit namespaces and hostnames. A
`workers.dev` hostname or a separate zone/domain is acceptable when cross-account
subdomain delegation is unavailable.

## 12. Private Backups

Sensitive cutover backups are stored outside the workspace:

```text
/Users/pgpenguin72/pg72-private-backups/2026-07-15-sso-cutover/
```

Files at handoff:

- `cloud-clipboard-pages-project-before-preview-removal.json`
- `cloud-clipboard-sso-preview.sql`
- `complete-production-promotion.sql`
- `pg72-id-pre-jwks-rotation.sql`
- `pg72-id-preview.sql`
- `pg72-oidc-test-rp-preview.sql`
- `retire-test-rp.sql`
- `steep-art-cf42-d1.sql`

All were verified mode `0600`. They contain sensitive identity/auth data or
resource configuration. Do not move them into the repository or upload them to
an unencrypted shared drive. Before relying on them for recovery, validate
checksums and import into a new isolated recovery database first.

## 13. Local Development

From the workspace root:

```bash
pnpm install --frozen-lockfile
pnpm --filter @pg72/id cf-typegen
pnpm --filter @pg72/test-rp cf-typegen
pnpm --filter @pg72/id db:migrate:local
pnpm --filter @pg72/test-rp db:migrate:local
pnpm --filter @pg72/id db:seed-test-rp:local
```

Create `apps/sso/.dev.vars` locally with development-only values. It is ignored
and must contain no production secret. The checked source should contain only
non-working placeholders.

Local Google callback:

```text
http://localhost:5173/callback/google
```

Run in separate terminals:

```bash
pnpm dev
pnpm dev:rp
```

Local URLs:

- PGID: `http://localhost:5173`
- OIDC test RP: `http://localhost:5174`

## 14. Verification and Release Gate

Minimum SSO gate:

```bash
pnpm --filter @pg72/id cf-typegen
pnpm --filter @pg72/id check
```

Current `check` runs typecheck, 27 workerd tests and production build.

Additional release checks:

```bash
cd apps/sso

# No pending remote migration
pnpm exec wrangler d1 migrations list PG72_ID_DB --remote

# Confirm no local secret file survived the Vite build
find dist -type f \( -name '.dev.vars' -o -name '.dev.vars.*' \) -print

# Startup profile / dry analysis
pnpm exec wrangler check startup \
  --config dist/pg72_id/wrangler.json \
  --outfile /tmp/pg72-id-startup.cpuprofile

# Dependency gate
pnpm audit --prod --audit-level high
```

The current test suite covers:

- discovery/JWKS metadata and PKCE advertisement;
- dynamic registration disabled;
- consent cannot be skipped;
- redirect normalization;
- D1 constraints;
- invitation/bootstrap/suspension/account deletion;
- resource-indicator rejection;
- request abort recovery;
- account authorization listing/revocation;
- CSRF/Origin protections;
- Passkey list ownership;
- Passkey rename;
- Passkey delete ownership;
- cross-origin Passkey delete rejection;
- fresh-session requirement for deleting the final Passkey.

The independent localhost RP has four tests covering its transaction/PKCE and
callback behavior.

## 15. Production Deployment Runbook

Run Wrangler from `apps/sso`, not the workspace root. The root package does not
directly expose a Wrangler binary, which can produce `Command "wrangler" not
found` for `pnpm exec wrangler`.

```bash
cd /Users/pgpenguin72/sso.pg72.tw/apps/sso

# 1. Verify identity and account before changing remote state
pnpm exec wrangler whoami

# 2. Check migrations and create a private D1 export for risky data changes
pnpm exec wrangler d1 migrations list PG72_ID_DB --remote

# 3. Build and test from workspace root or app directory
pnpm check

# 4. Inspect the generated production config and secret artifact scan
find dist -type f \( -name '.dev.vars' -o -name '.dev.vars.*' \) -print

# 5. Deploy the Vite-generated Worker bundle/assets
pnpm exec wrangler deploy --config dist/pg72_id/wrangler.json
```

After deployment:

```bash
curl -fsS https://sso.pg72.tw/health
curl -fsS https://sso.pg72.tw/ready
curl -fsS https://sso.pg72.tw/.well-known/openid-configuration
curl -fsS https://sso.pg72.tw/.well-known/jwks.json

# Must be 401 without a session
curl -sS -o /dev/null -w '%{http_code}\n' \
  https://sso.pg72.tw/passkey/list-user-passkeys

pnpm exec wrangler deployments list --name pg72-id --json
```

Static Assets may need several seconds to propagate. Verify the `index.html`
hashed JS/CSS names from more than one edge address and confirm the new JS asset
contains the expected management labels before declaring success.

Interactive release checks must be done by the owner:

1. Google sign in.
2. Dashboard loads and `/get-session` stays healthy.
3. Register/authenticate a production `sso.pg72.tw` Passkey.
4. Rename the Passkey and refresh the page.
5. Delete only the obsolete credential and verify the remaining Passkey still
   signs in.
6. Confirm deleting the last Passkey requires recent sign-in when the session is
   older than 10 minutes.

## 16. Rollback Runbook

Code/assets rollback:

```bash
cd /Users/pgpenguin72/sso.pg72.tw/apps/sso
pnpm exec wrangler deployments list --name pg72-id --json
pnpm exec wrangler versions list --name pg72-id --json
pnpm exec wrangler rollback <KNOWN_GOOD_VERSION_ID>
```

Known pre-Passkey-management code version:

```text
0367d345-dcad-4a77-b02c-785e111a4adf
```

The intermediate UI-only version is:

```text
0de21c1c-b3db-4efa-954f-f6a8fda53e6f
```

The final version with Worker-side fresh-session/audit policy is:

```text
eafd3330-9299-44f6-baa5-df57bfa41ad6
```

After rollback, repeat health, discovery, JWKS, session, static asset and Google/
Passkey interactive checks. A Worker rollback does not undo D1 writes or secret
changes.

D1 recovery must never begin by overwriting production. Restore the private SQL
export into a new isolated database, validate schema/counts/JWKS decryptability,
and only then plan a binding switch. Preserve issuer, user `sub`, Passkey
credentials, client IDs and active signing keys.

## 17. Copy Production Cutover (Not Yet Done)

The Copy source integration is substantial and should not be reimplemented from
scratch. It already includes:

- PGID OIDC confidential provider;
- Authorization Code + PKCE + state + nonce;
- verified email requirement at the callback;
- stable SSO `sub` binding to a local Copy user;
- independent six-digit guest-code provider;
- D1-backed opaque SSO token-vault session ID in the Auth.js JWT;
- AES-GCM encrypted access/refresh tokens in D1;
- refresh lease/generation compare-and-swap behavior;
- fail-closed handling for abandoned/unknown refresh write-back;
- server-side token-session revocation on logout;
- guest `auth_version` invalidation and D1 rate limiting.

Current blockers:

- no production `pg72-copy` OAuth client exists in SSO D1;
- Copy's local source changes are not confirmed deployed to the canonical Pages
  production deployment;
- Pages production lacks `PG72_ID_ISSUER`, `PG72_ID_CLIENT_ID`,
  `PG72_ID_CLIENT_SECRET`, and `PG72_TOKEN_VAULT_KEY_V1`;
- Pages production still has old direct Google binding names;
- production D1 migration state for the Copy SSO token vault must be checked;
- back-channel logout/central `sid` is not implemented.

Safe cutover order:

1. Review and commit the Copy dirty worktree. Run its lint/tests/build.
2. Export the production `cloud-clipboard` D1 privately.
3. Apply/verify Copy SSO migrations against a Preview database in the new
   isolated Cloudflare account first.
4. Implement/use an authenticated SSO admin operation to create confidential
   client `pg72-copy`. Do not insert a plaintext client secret manually.
5. Exact redirect URI:

   ```text
   https://copy.pg72.tw/api/auth/callback/pg72-id
   ```

6. Exact post-logout URI and client metadata must be reviewed before creation.
7. Required scopes: `openid profile email offline_access`.
8. Grant types: `authorization_code refresh_token`.
9. Token endpoint auth: `client_secret_basic`.
10. Require PKCE and consent; client is not public.
11. Store the one-time client secret and independent token-vault key only in
    Pages production secret/env storage.
12. Deploy Copy production without deleting the six-digit provider.
13. Test a new PG72 user, an existing bound user, guest-code login, refresh,
    authorization revoke, sign-out, file ownership and error/retry states.
14. Remove the old direct Google provider/secrets only after PGID production
    login and rollback are proven.

Do not reuse the deleted `pg72-copy-preview` client or its secret.

## 18. Other Service Integration Status

### Link

Local source is integrated with `oauth4webapi` confidential OIDC, PKCE, state,
nonce, ID token/UserInfo validation, stable `sso_subject`, exact Origin and safer
target URLs. It has not completed isolated Preview or production cutover.
Remaining: separate Preview D1/account, central `sid`, back-channel logout and
full browser flow.

### Status / XUGOU

Local source replaces browser `localStorage` bearer auth with hashed opaque D1
sessions and host-only cookies. OIDC, PKCE/state/nonce/replay, role checks and
agent IDOR fixes exist locally. Agent machine authentication remains separate.
It has not completed isolated Preview/production cutover or back-channel logout.

The original source previously contained a hard-coded Telegram credential. Seed
paths were disabled and source scans stopped matching it, but deletion from source
does not revoke the credential. The owner must rotate/revoke it at Telegram if it
was ever valid.

### Upload Admin

Local FastAPI/Authlib OIDC work removes Cloudflare Access and development auth
bypasses. It uses immutable `sub`, role checks, SQLite opaque sessions, encrypted
tokens, Origin + CSRF and separate public upload capabilities. It needs a VPS
Preview and reverse-proxy/origin-lockdown verification.

### File Browser

Use a pinned stable upstream release. Prefer an external OIDC gateway and proxy
auth header. The origin must only accept traffic from the gateway, and the
gateway must overwrite user-supplied identity headers. Do not deploy the supplied
upstream source snapshot as the long-term fork.

### Webmail / Roundcube

Use a pinned stable Roundcube release; the supplied `1.8-git` snapshot is not a
production package. Roundcube supports Generic OIDC and related flows, but web
SSO does not automatically solve IMAP/SMTP authentication. Confirm whether the
mail server supports `XOAUTH2`/`OAUTHBEARER`; otherwise design a separate app
password or short-lived credential bridge.

## 19. Next Work, in Recommended Order

### P0: Owner Acceptance of This Deployment

- Open `https://sso.pg72.tw`.
- Go to Security -> Passkeys.
- Rename each credential and refresh to verify persistence.
- Identify the credential that actually authenticates at `sso.pg72.tw`.
- Delete only the obsolete Preview credential.
- Verify Google and remaining production Passkey login.

### P0: Put the SSO Workspace Under Private Version Control

- create a private repository;
- add CI for typecheck, workerd tests, build, audit, secret scan and artifact scan;
- commit the current lockfile and generated binding types;
- protect the production branch;
- do not include `.dev.vars`, backups or Cloudflare auth profiles.

### P1: Isolated Preview Account

- create/invite a separate Cloudflare account;
- create Preview-only Wrangler profile/token with least privilege;
- create separate SSO D1, queues, DLQ, secrets and Google callback;
- use synthetic/non-production identity data;
- deploy Copy/Link/Status Preview there;
- never reuse production secrets or bindings.

### P1: Production Copy SSO

Follow Section 17. Preserve six-digit guest login. Do not switch Link/Status at
the same time; keep the blast radius to one relying party.

### P1: Audit and Recovery

- audit Google/Passkey login success/failure and Passkey registration;
- populate actor/session/request metadata without storing tokens or raw PII;
- implement recovery codes;
- register two independent admin Passkeys;
- perform JWKS rotation and D1 restore drills;
- configure DLQ alerts.

### P2: `sid` and Back-Channel Logout

- define versioned logout-token contract;
- include/track central `sid`;
- record visited client/session relationships;
- deliver replay-safe signed logout tokens through Queue;
- implement each RP's idempotent back-channel endpoint;
- add retry, DLQ, status and operator recovery.

### P2: Link, Status and Upload Preview

Move one service at a time through the isolated Preview gate and only then plan
production cutover.

### P3: Legacy Services and Public Registration

Package File Browser/Roundcube from stable upstream, deploy gateway/origin
controls, add Turnstile/abuse/privacy/retention, perform independent security
testing, and only then consider `REGISTRATION_MODE=public`.

## 20. Operational Do/Do-Not Checklist

Do:

- run `wrangler whoami` before any remote command;
- export D1 before auth schema/JWKS/client/token cleanup;
- use exact origins and redirect URIs;
- keep core/plugins exact-pinned and aligned;
- use request-scoped auth creation;
- await promises or pass them to `executionCtx.waitUntil`;
- use D1/Queue bindings from the Worker rather than Cloudflare REST API;
- check both protocol response and browser session after login changes;
- test edge asset propagation after deploy;
- redact PII/tokens from logs and reports.

Do not:

- delete `pg72-id-preview` D1;
- share production D1/secrets with Preview;
- rotate `BETTER_AUTH_SECRET` casually;
- disable consent for first-party clients;
- enable dynamic registration;
- remove Copy's six-digit guest code;
- merge guest and SSO identities by email;
- store tokens in browser `localStorage`;
- put secret values in Wrangler vars/source/docs;
- deploy upstream File Browser/Roundcube snapshots directly;
- reset dirty service worktrees;
- claim Production GO before logout/recovery/security gates are complete.

## 21. Reference Documents

- `README.md`: local setup and provisioning summary
- `SECURITY.md`: release gate and accepted vulnerability
- `codex.md`: canonical architecture and service-by-service design
- Better Auth Passkey documentation:
  `https://better-auth.com/docs/plugins/passkey`
- Cloudflare Workers best practices:
  `https://developers.cloudflare.com/workers/best-practices/workers-best-practices/`
- Wrangler commands:
  `https://developers.cloudflare.com/workers/wrangler/commands/`
- Cloudflare Pages Preview configuration:
  `https://developers.cloudflare.com/pages/configuration/preview-deployments/`

## 22. Final State at Handoff

- Passkey list/rename/delete UI is deployed.
- Rename/delete ownership and exact-Origin protections are tested.
- Final-Passkey deletion requires a fresh session.
- SSO Worker version `eafd3330-9299-44f6-baa5-df57bfa41ad6` is active.
- Production health/session/discovery/JWKS/asset smoke tests pass.
- Copy production remains available but is not yet a PGID client.
- All old production-account Preview Pages bindings are empty and automatic
  Preview is disabled.
- D1 count is eight; the live PG72 identity D1 retains the historical name
  `pg72-id-preview`.
- No SSO migration is pending.
- The next human action is to manage/test the two real Passkeys in the browser,
  then establish private version control and an isolated Preview account before
  cutting over Copy production.
