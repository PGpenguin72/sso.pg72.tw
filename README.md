# PG72 ID

PG72 ID is the custom identity provider for PG72 services. Phase 0 runs on Cloudflare Workers and D1 and provides:

- Google sign-in and Passkey authentication;
- OAuth 2.1 / OpenID Connect Authorization Code with PKCE S256;
- host-only central sessions, device revocation, invitations, account suspension, and audit events;
- an independent OIDC relying party based on `oauth4webapi`;
- workerd regression tests for discovery, security headers, registration policy, request aborts, D1 constraints, PKCE transactions, and callback replay.

The canonical architecture and migration decisions are in [`codex.md`](./codex.md). A production canary is deployed at `https://sso.pg72.tw`, but production relying parties must not switch traffic until the production Google login and newly registered `sso.pg72.tw` Passkey gate passes.

## Workspace

```text
apps/sso       PG72 ID Worker, React account center, D1 migrations
apps/test-rp   Independent OIDC protocol relying party
```

The service sources under `原專案代碼/` are migration inputs. They are not modified or built by this workspace.

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

Edit `apps/sso/.dev.vars` with a random local secret and Google credentials. The checked-out file is ignored and contains non-working development placeholders.

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

- PG72 ID: `http://localhost:5173`
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

The `pg72-id` Worker was deployed on 2026-07-15 with the promoted identity D1, production queues/secrets, exact `sso.pg72.tw` custom domain, and production issuer/Passkey settings. Health, D1 readiness, discovery, JWKS, security headers, and Google authorization redirect smoke tests pass. The obsolete encrypted JWKS row and all sessions were rotated after the production secret mismatch was found; users must sign in again. The remaining interactive gate is a real Google callback followed by registration and authentication with a new `sso.pg72.tw` Passkey.

Production completion checklist:

1. Production queues, secrets, exact bindings, custom domain, and migrations are configured.
2. The promoted identity database is now production-only; the old Preview Worker, domain, queues, and Preview OAuth grants were removed.
3. Do not run the local test client seed against production. The remote test client and its grants were removed.
4. Create production OAuth clients through an authenticated admin operation with exact HTTPS redirect URIs.
5. Configure Google callback `https://sso.pg72.tw/callback/google`.
6. Re-run the real Google callback, register a new production Passkey, and verify Passkey login before changing Phase 0 status.

Dynamic client registration, passwords, Email OTP, TOTP, cross-subdomain cookies, and Cloudflare Access authentication are intentionally disabled.
