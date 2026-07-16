# PGID

PGID is the custom identity provider for PG72 services. Phase 0 runs on Cloudflare Workers and D1 and provides:

- Google sign-in and Passkey authentication;
- optional Discord, GitHub, Facebook, Apple, and Telegram sign-in that remains hidden unless its credentials are configured;
- OAuth 2.1 / OpenID Connect Authorization Code with PKCE S256, EdDSA ID tokens, and a published JWKS;
- admin/developer-managed OAuth clients (dynamic registration disabled), mandatory consent, and the `bootadmin`/`admin`/`developer`/`user` platform role model;
- host-only central sessions, device revocation, invitations, account suspension, and audit events;
- versioned D1 migrations through local source `0014`; the latest production record remains applied through `0012` until the owner verifies/applies `0013` and `0014` remotely;
- a tightly scoped mail introspection path for Dovecot: local source authorizes only `pgid-mail-introspect` to inspect eligible `pg72-webmail` access tokens and disclose verified email; this path is not deployed or provisioned in production;
- Passkey step-up before every OAuth client mutation, using a one-time session/user-bound challenge, required user verification, and a D1 session timestamp; this path is implemented and tested locally but not migrated, deployed, independently reviewed, or smoke-tested in production;
- an independent OIDC relying party based on `oauth4webapi`;
- workerd regression tests for discovery, security headers, registration policy, request aborts, D1 constraints, PKCE transactions, and callback replay.

The canonical architecture and migration decisions are in [`codex.md`](./codex.md). PGID is deployed at `https://sso.pg72.tw` as an invite-only beta, and deployment records show Copy and Link using it in production. This is not full Production GO: public registration, central `sid`/back-channel logout, recovery drills, and other security gates remain incomplete.

## Documentation

| Document | Purpose |
| --- | --- |
| [`codex.md`](./codex.md) | Canonical architecture and security baseline (single source of truth). |
| [`handoff.md`](./handoff.md) | Current operational state, runbooks, and rollback. |
| [`SECURITY.md`](./SECURITY.md) | Release gate and the accepted Phase 0 finding. |
| [`docs/about-PGID.md`](./docs/about-PGID.md) | Product introduction; what PGID is and why. Also used by the frontend `/about` page. |
| [`docs/api/PGID-integration.md`](./docs/api/PGID-integration.md) | Concise integration reference: endpoints, scopes, claims, token lifetimes, client auth, and copyable `oauth4webapi`/generic examples. |
| [`wiki/`](./wiki/SUMMARY.md) | GitBook-compatible tutorial site (content source for `wiki.sso.pg72.tw`): user guides and developer walkthroughs. |
| [`docs/integration-plans/`](./docs/integration-plans/) | Per-service integration plans (File Browser, Roundcube). |

## Registration Policy

The deployed `REGISTRATION_MODE` in `apps/sso/wrangler.jsonc` is currently `"invite"`. The code supports and tests both modes, but the switch to `"public"` requires the `codex.md` §9.2 gate, explicit owner approval, and a production deployment. Invitations stay fully functional in either mode; a pending invitation still assigns its role (for example `admin`) and is consumed on first sign-in.

Current safeguards in public mode:

- A first Google sign-in creates the account only when Google asserts a verified email; unverified emails are rejected in both modes.
- Telegram does not provide an email, so it never creates a PGID account in either mode. It can sign in only after that Telegram identity was explicitly linked from an authenticated PGID session.
- Passkey registration still requires an existing account and an authenticated session.
- New-account creation has its own per-IP Workers Rate Limiting budget (`REGISTRATION_RATE_LIMITER`, 5/min), stricter than the sign-in limiter (30/min). The budget is consumed before any denial audit write or invitation lookup so those cannot be spammed.
- Suspended accounts and deleted (missing) users are blocked at session creation, so public mode does not bypass suspension. A deleted user who re-registers receives a brand-new `sub`.
- Registration denials never reveal whether an account exists.

Known-incomplete gates that block opening registration (tracked in `codex.md` §9.2): Turnstile/bot challenge, Terms/Privacy consent recording, abuse detection and response runbook, independent security review, OIDC conformance/security testing, DAST, SAST/secret/IaC scan gates, load testing, backup-restore and key-rotation drills, restricted state for new accounts, and full back-channel logout rollout.

## Workspace

```text
apps/sso       PGID Worker, React account center, D1 migrations
apps/test-rp   Independent OIDC protocol relying party
```

The service sources under `原專案代碼/` are migration inputs. They are not modified or built by this workspace.

## Relying Parties

PG72 services integrate as standard OIDC relying parties. Integration status (see `codex.md` §18 and `handoff.md` for detail):

| Service | Integration | Status |
| --- | --- | --- |
| Copy (`copy.pg72.tw`) | Native OIDC confidential client + PKCE, guest-code path kept separate | **Production live** (cutover 2026-07-16; `pg72-copy` client). Guest six-digit code retained. |
| Link (`link.pg72.tw`) | `oauth4webapi` BFF, stable `sub` session | **Production live** (cutover 2026-07-16; `pg72-link` client, `client_secret_post`). Central `sid`/back-channel logout still pending. |
| Status (`status.pg72.tw`) | OIDC BFF + D1 opaque session | Local integration complete; Preview and back-channel logout pending. |
| Upload admin (`upload.pg72.tw/admin`) | Authlib OIDC + SQLite session (`client_secret_post`) | Local integration complete; VPS Preview/cutover runbook prepared. |
| File Browser (`file.pg72.tw`) | oauth2-proxy gateway + proxy auth header | Deploy config prepared (`deploy/pgid/`); not yet deployed. |
| Roundcube (`webmail.pg72.tw`) | Native Generic OIDC + Dovecot XOAUTH2 for mail | Owner selected Dovecot Path A. PGID prerequisite is implemented at local commit `9efdece` and passed the complete local gate (166 SSO tests, 4 RP tests); it is not deployed, `pgid-mail-introspect` is not provisioned, and the VPS has not been cut over. |

Copy and Link have switched production traffic to PGID. Relying parties must use `client_secret_post` for the token endpoint (the provider's HTTP Basic parsing is not RFC-6749-percent-decode compatible). See `handoff.md` for cutover records.

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

Copy tracked `apps/sso/.dev.vars.example` to ignored `apps/sso/.dev.vars`, then replace the required placeholders with a random local secret and development Google credentials. Optional provider values are intentionally empty so copying the template cannot enable a provider; only fill them in when testing that provider. Never commit the real `.dev.vars`.

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
pnpm typecheck
pnpm test
pnpm build
pnpm audit --prod --audit-level high
```

The audit currently reports the accepted Moderate `GHSA-p2fr-6hmx-4528`. Its constrained exposure and temporary controls are documented in [`SECURITY.md`](./SECURITY.md). A High or Critical advisory fails the release gate.

The recorded full gate for the mail-introspection implementation at `9efdece` is 166 passing SSO tests and 4 passing RP protocol tests. That is a local-source verification record, not evidence of a production deployment or smoke test.

## Cloudflare Provisioning

### Preview

The temporary Preview resources in the production Cloudflare account were retired on 2026-07-15 after their data was exported. The Preview Worker, domain, queues, test RP, Copy deployments, Copy D1 binding, and Preview-only OAuth client were removed. Cloud Clipboard automatic Preview deployments are disabled so a branch push cannot recreate a Preview that uses production-account resources.

Future Preview environments must live in a separate Cloudflare account with separate D1 databases, queues, secrets, domains, Google callback, and Rate Limiting namespaces. The local test RP remains for protocol regression coverage.

- OAuth clients cannot skip consent. Each account must approve a new client or newly requested scope before authorization continues.
- The account center lists approved applications and can revoke their consent, pending authorization codes, access tokens, and refresh tokens.
- Self-service account deletion requires a fresh session. The bootstrap administrator is protected; other `user` and `admin` accounts may delete themselves.

Consent revocation prevents future token use and requires the application to request consent again. It does not yet terminate an application's own local session cookie; back-channel logout or RP-side session validation remains required for immediate cross-site logout.

Do not deploy the removed Preview configurations into the production account. Preview secrets must be created only in the future isolated account and must never be stored in source control.

### Production

The `pg72-id` Worker is deployed with the production identity D1, queues/secrets, exact `sso.pg72.tw` custom domain, and production issuer/Passkey settings. Existing records report migrations through `0012`, successful smoke checks, and Copy/Link cutover. The obsolete encrypted JWKS row and sessions were rotated after the 2026-07-15 production secret mismatch. These are deployment records, not a claim that the full gate below has passed.

Full Production GO checklist:

1. Production queues, secrets, exact bindings, custom domain, and migrations are configured.
2. The promoted identity database is now production-only; the old Preview Worker, domain, queues, and Preview OAuth grants were removed.
3. Do not run the local test client seed against production. The remote test client and its grants were removed.
4. Create production OAuth clients through an authenticated admin operation with exact HTTPS redirect URIs.
5. Configure Google callback `https://sso.pg72.tw/callback/google`.
6. Re-run real Google and production Passkey flows, verify Copy/Link sign-out, and complete central `sid`/back-channel logout, recovery, rotation, restore, DLQ, and independent-review gates before changing the beta status.

Mail Path A remains a separate owner-run rollout:

1. Review the locally implemented Passkey step-up and verify its session/challenge binding, UV, replay, expiry, and missing-Passkey behavior independently; production still lacks migration `0014` and this Worker version.
2. Verify the exact production `pg72-webmail` client metadata and take a private production D1 backup.
3. Owner applies migrations `0013` and `0014` in order, then deploys the verified Worker source with Rate Limiting namespaces `1004` and `1005` bound as configured.
4. After Passkey step-up, use a same-origin PGID admin session less than 10 minutes old to provision `pgid-mail-introspect`; immediately store its one-time secret in the approved secret store, never source, logs, issues, or chat.
5. Verify eligible active, ineligible inactive, and bad-credential `401` production behavior. Verify rate-limit `429` and limiter-failure `503` only in isolated Preview or a controlled local test, never by flooding or breaking production.
6. Cut over Dovecot/Roundcube only in that owner-controlled window with the rollback in [`handoff.md`](./handoff.md) ready. This documentation reconciliation ran no remote command and changed no production or VPS state.

Dynamic client registration, passwords, Email OTP, TOTP, cross-subdomain cookies, and Cloudflare Access authentication are intentionally disabled.
