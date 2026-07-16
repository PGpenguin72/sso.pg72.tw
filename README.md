# PGID

PGID is the custom identity provider for PG72 services. Phase 0 runs on Cloudflare Workers and D1 and provides:

- Google sign-in and Passkey authentication;
- optional Discord, GitHub, Facebook, Apple, and Telegram sign-in that remains hidden unless its credentials are configured;
- OAuth 2.1 / OpenID Connect Authorization Code with PKCE S256, EdDSA ID tokens, and a published JWKS;
- nonempty central `sid` claims on every user ID token, with refresh issuance bound to the same live user session;
- admin/developer-managed OAuth clients (dynamic registration disabled), mandatory consent, and the `bootadmin`/`admin`/`developer`/`user` platform role model;
- host-only central sessions, device revocation, invitations, account suspension, and audit events;
- versioned D1 migrations through local source `0016`: `0013` normalizes confidential client authentication, `0014` adds Passkey step-up state, `0015` enforces global provider-identity ownership, and `0016` adds one-time public-registration intents plus immutable legal-acceptance history; the latest production record remains applied through `0012` until the owner verifies and applies the pending migrations in order;
- a tightly scoped mail introspection path for Dovecot: local source authorizes only `pgid-mail-introspect` to inspect eligible `pg72-webmail` access tokens and disclose verified email; this path is not deployed or provisioned in production;
- Passkey step-up before every OAuth client mutation, using a one-time session/user-bound challenge, required user verification, and a D1 session timestamp; this path is implemented and tested locally but not migrated, deployed, independently reviewed, or smoke-tested in production;
- an independent OIDC relying party based on `oauth4webapi`;
- workerd regression tests for discovery, security headers, registration policy, request aborts, D1 constraints, PKCE transactions, and callback replay.

The canonical architecture and migration decisions are in [`codex.md`](./codex.md). PGID is deployed at `https://sso.pg72.tw` as an invite-only beta, and deployment records show Copy and Link using it in production. This is not full Production GO: public registration, the visited-client ledger and back-channel logout rollout, recovery drills, and other security gates remain incomplete.

## Documentation

| Document | Purpose |
| --- | --- |
| [`codex.md`](./codex.md) | Canonical architecture and security baseline (single source of truth). |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Local contribution workflow, verification gate, and documentation sync rules. |
| [`SECURITY.md`](./SECURITY.md) | Release gate and the accepted Phase 0 finding. |
| [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md) | License provenance for Better Auth, Inter, VitePress, and other distributed third-party components. |
| [`docs/about-PGID.md`](./docs/about-PGID.md) | Product introduction; what PGID is and why. Also used by the frontend `/about` page. |
| [`docs/api/PGID-integration.md`](./docs/api/PGID-integration.md) | Concise integration reference: endpoints, scopes, claims, token lifetimes, client auth, and copyable `oauth4webapi`/generic examples. |
| [`wiki/`](./wiki/SUMMARY.md) | GitBook-compatible tutorial site (content source for `wiki.sso.pg72.tw`): user guides and developer walkthroughs. |

## Registration Policy

The deployed `REGISTRATION_MODE` in `apps/sso/wrangler.jsonc` is currently `"invite"`. The code supports and tests both modes, but the switch to `"public"` requires the `codex.md` §9.2 gate, explicit owner approval, and a production deployment. Invitations stay fully functional in either mode; a pending invitation still assigns its role (for example `admin`) and is consumed on first sign-in.

Current safeguards in public mode:

- A first Google sign-in creates the account only when Google asserts a verified email; unverified emails are rejected in both modes.
- Telegram does not provide an email, so it never creates a PGID account in either mode. It can sign in only after that Telegram identity was explicitly linked from an authenticated PGID session.
- Passkey registration still requires an existing account and an authenticated session.
- Public account creation is Google-only and requires an explicit current Terms/Privacy acceptance plus a Turnstile token that the Worker verifies server-side for the exact PGID hostname and registration action. A successful challenge creates a short-lived, one-time opaque intent whose raw value is returned once and stored only as a SHA-256 digest. The registration start exchanges it for an independent reference bound to Better Auth's actual OAuth state; only that reference crosses protected OAuth state. Optional social providers remain available to existing or explicitly linked accounts, but cannot create public users.
- D1 records the accepted Terms/Privacy version identifiers and server-side intent issuance time with the new user. Database triggers require the three acceptance fields together, preserve the initial values, and write an acceptance-history row in the user transaction. Direct history UPDATE/DELETE is rejected while the account exists; deleting the parent account removes its account-scoped history through the declared privacy-policy cascade.
- New-account creation has its own per-IP Workers Rate Limiting budget (`REGISTRATION_RATE_LIMITER`, 5/min), stricter than the sign-in limiter (30/min). The budget is consumed before any denial audit write or invitation lookup so those cannot be spammed.
- Suspended accounts and deleted (missing) users are blocked at session creation, so public mode does not bypass suspension. A deleted user who re-registers receives a brand-new `sub`.
- Registration denials never reveal whether an account exists.

Known-incomplete gates that block opening registration (tracked in `codex.md` §9.2): production deployment/configuration and independent review of the local Turnstile/legal-acceptance slice, owner approval of the live policy version identifiers, abuse detection and response runbook, OIDC conformance/security testing, DAST, SAST/secret/IaC scan gates, load testing, backup-restore and key-rotation drills, restricted state for new accounts, and full back-channel logout rollout.

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
| Copy (`copy.pg72.tw`) | Native OIDC confidential client + PKCE, guest-code path kept separate | **Production live**. Guest six-digit code retained. |
| Link (`link.pg72.tw`) | `oauth4webapi` BFF, stable `sub` session | **Production live**. Central `sid`/back-channel logout still pending. |
| Status (`status.pg72.tw`) | OIDC BFF + D1 opaque session | Local integration complete; Preview and back-channel logout pending. |
| Upload admin (`upload.pg72.tw/admin`) | Authlib OIDC + SQLite session (`client_secret_post`) | Local integration complete; Preview and cutover pending. |
| File Browser (`file.pg72.tw`) | oauth2-proxy gateway + proxy auth header | Planned; not yet deployed. |
| Roundcube (`webmail.pg72.tw`) | Native Generic OIDC + Dovecot XOAUTH2 for mail | PGID prerequisite is implemented locally; deployment, service-client provisioning, and mail cutover remain pending. |

Copy and Link have switched production traffic to PGID. Relying parties must use
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

Copy tracked `apps/sso/.dev.vars.example` to ignored `apps/sso/.dev.vars`, then replace the required placeholders with a random local secret and development Google credentials. The template exercises public mode, so it also needs a hostname-scoped Turnstile test widget and approved local Terms/Privacy version identifiers; set `REGISTRATION_MODE=invite` instead when that flow is not under test. Optional provider values are intentionally empty so copying the template cannot enable a provider; only fill them in when testing that provider. Never commit the real `.dev.vars`.

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
pnpm audit --audit-level high
```

`pnpm check` is the canonical repository gate. It runs the clean-build-output
regression and workspace package checks, covering type checks, workerd and
relying-party protocol tests, Wiki route/link/header validation, and production
and static builds.

The audit covers runtime, build, and development dependencies so tooling
advisories cannot bypass the High or Critical release gate.

The audit currently reports the accepted Moderate `GHSA-p2fr-6hmx-4528`. Its constrained exposure and temporary controls are documented in [`SECURITY.md`](./SECURITY.md). A High or Critical advisory fails the release gate.

These commands verify local source only. They do not deploy, migrate remote D1,
provision clients, or provide a production smoke-test record.

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

The `pg72-id` Worker is deployed with a production identity D1, queues/secrets,
the exact `sso.pg72.tw` custom domain, and production issuer/Passkey settings.
Existing records report migrations through `0012`; an authorized operator must
verify current remote state before a maintenance operation. Deployment history is
not evidence that the full gate below has passed.

The committed `database_id` is a local-development placeholder. Configure the
reviewed production binding through the deployment environment before any remote
operation; never treat the placeholder as a production resource.

Full Production GO checklist:

1. Production queues, secrets, exact bindings, custom domain, and migrations are configured.
2. The promoted identity database is now production-only; the old Preview Worker, domain, queues, and Preview OAuth grants were removed.
3. Do not run the local test client seed against production. The remote test client and its grants were removed.
4. Create production OAuth clients through an authenticated admin operation with exact HTTPS redirect URIs.
5. Configure Google callback `https://sso.pg72.tw/callback/google`.
6. Re-run real Google and production Passkey flows, verify Copy/Link sign-out, and complete the visited-client ledger/back-channel logout rollout, recovery, rotation, restore, DLQ, and independent-review gates before changing the beta status.

Mail Path A remains a separate owner-run rollout:

1. Review the locally implemented Passkey step-up and verify its session/challenge binding, UV, replay, expiry, and missing-Passkey behavior independently; production still lacks migration `0014` and this Worker version.
2. Verify the exact production `pg72-webmail` client metadata and take a private production D1 backup.
3. Run the provider-identity duplicate preflight in `codex.md` §0.1, apply the reviewed pending migrations in numeric order (`0013`, `0014`, `0015`, then `0016`), and deploy the verified Worker source with `PASSKEY_STEP_UP_MAX_AGE_SECONDS=600` plus Rate Limiting namespaces `1004` and `1005` bound as configured. Migration `0016` is required by this Worker schema even while production remains invite-only; applying it does not authorize changing `REGISTRATION_MODE`.
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
