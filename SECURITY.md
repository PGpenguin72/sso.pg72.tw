# Security Policy

PGID currently runs as a deployed, invite-only production beta. Existing deployment records show Copy and Link using PGID for production sign-in. Public registration remains disabled.

This deployed state is not the same as full Production GO or general-public approval. Local source now emits and validates the central ID-token `sid`, but the visited-client ledger, replay-safe back-channel logout, recovery/rotation drills, independent review, and other gates below are still incomplete; no document may treat production traffic alone as proof that those controls passed.

The repository's local source now includes the narrowly scoped Mail Path A introspection prerequisite, Passkey step-up for every OAuth client mutation, and public-registration prerequisites using Turnstile, versioned legal acceptance, and persistent restricted-account access. Production has none of migrations `0013`/`0014`/`0015`/`0016`/`0017` or this Worker version; `pgid-mail-introspect` has not been provisioned, no public-registration bindings have been configured, no remote D1 operation was performed, and the mail VPS has not been cut over. These local results must not be represented as production behavior.

## Reporting

Do not open a public issue containing secrets, tokens, personal data, or an
exploit against a live PG72 service. Email
[`contact@pg72.tw`](mailto:contact@pg72.tw?subject=PGID%20security%20report) with:

- affected endpoint and environment;
- minimal reproduction steps;
- expected and observed behavior;
- impact assessment;
- logs with credentials and personal data removed.

## Invite Beta Release Gate

Changes to the deployed invite beta require:

- strict TypeScript, workerd tests, production builds, dependency audit, and secret scan appropriate to the change;
- no open Critical or High finding;
- every accepted Moderate finding recorded with an owner, compensating control, and expiry;
- affected Google, Passkey, OIDC negative/replay, revoke, and request-abort checks;
- an explicit rollback path and post-release smoke checks.

Passing this narrower gate permits an invite-beta release only. It does not authorize public registration or a full Production GO claim.

## Automated Source Assurance

Run the tracked local gates from a frozen install:

```bash
pnpm check
pnpm security:tools:install
pnpm security:check
pnpm dast:local
```

`pnpm security:check` combines type-aware Worker Promise analysis, required
checksum-pinned Gitleaks full-history scanning, an explicit bounded/redacted
tracked/untracked/ignored-sensitive-path scan plus captured Secretlint,
actionlint and recursive workflow/package-script allowlists with exact scoped
environment key/value and expression contracts, exact source and generated
Wrangler binding/resource contracts, dependency-advisory
reconciliation, a production Worker dry-run artifact scan, and a
dependency/license inventory. The artifact gate uses the same redacted secret
families for text and bounded binary strings and rejects source maps, private
machine paths, unexpected files, binding/config drift, and size regressions. CI
keeps only the redacted inventories for seven days. Assignment keys are
case/separator-normalized only after bounded declaration/object-key parsing;
source fixture and reviewed generated enum/metadata/fallback-sentinel allowances
are exact raw-path, normalized-key, complete-value triples, never placeholder
substrings. Workflow
environment keys/values are restricted by a code-owned allowlist; all
`CLOUDFLARE_*`, legacy `CF_*`, and `WRANGLER_*` keys are independently denied.
Unsafe diagnostic paths are normalized and represented only by a short SHA-256
identifier.

`pnpm dast:local` starts only ephemeral loopback Workers with synthetic values
and fresh local D1 state. Its credential-free probes cover health/readiness,
discovery, JWKS public-key shape, OIDC error surfaces, resource-indicator
rejection, dynamic-registration denial, logout/admin unauthenticated behavior,
security/cache headers, and a cross-Origin mutation denial. This baseline does
not cover real login, consent, authenticated admin/gateway/logout behavior,
abuse/load testing, or an independent review.

The separate `Isolated Preview DAST` workflow is manual and targets only the
exact origin committed to `security/dast-policy.json` and repeated in the
protected `isolated-preview` environment. A job-level guard permits only owner
`PGpenguin72` on `refs/heads/main`, including reruns, before any step starts.
The approved origin is intentionally `null` until the owner commits the actual
`pg72-id-preview.<account-subdomain>.workers.dev` origin, so the workflow
currently fails before any DAST HTTP request. Production, custom domains,
Pages, lookalikes, credentials, and URL paths are rejected. This workflow has
not been run or treated as Preview evidence by this source change. See
[`docs/runbooks/release-security.md`](./docs/runbooks/release-security.md).

## Full Production GO and Public Registration Gate

Before enabling `REGISTRATION_MODE=public` or declaring full Production GO, complete and record:

- independent security review and OIDC conformance/security testing;
- authenticated DAST across auth, OIDC, admin, gateway, and logout endpoints in
  an isolated Preview, in addition to the credential-free local baseline;
- run and retain the automated SAST, dependency, secret, workflow/IaC/config,
  and dry-run artifact gates for the exact release candidate;
- a central visited-client ledger, replay-safe back-channel logout, retry/DLQ alerting, and RP logout verification;
- recovery-code/break-glass, signing-key rotation, D1 restore, and Queue retry/DLQ drills;
- deploy, configure, independently review, and smoke-test the locally implemented Turnstile, versioned Terms/Privacy acceptance, and restricted-account paths after applying migrations `0016` and `0017`; the owner must approve the exact live policy versions, validate the initial abuse thresholds in Preview, assign an operator, and test external alert delivery;
- deploy and independently review the locally implemented Passkey step-up for high-risk system-client provisioning and secret rotation; production must apply migration `0014`, and the session-age freshness check remains an additional condition rather than a substitute;
- no unresolved Critical or High finding; every accepted Medium still needs an owner, deadline, and compensating control.

The canonical checklist is [`codex.md`](./codex.md) §9.2. The deployed configuration remains `invite` until that gate passes and the owner explicitly approves and deploys the switch.

The verified-email enrollment boundary applies to every new account. Telegram Login Widget payloads contain no email, so an unmatched Telegram identity is rate-limited, audited without its Telegram ID or other PII, and rejected in both `invite` and `public` modes. Telegram may authenticate only an active account to which that provider identity was explicitly linked from a standard authenticated PGID session; an existing link remains an ordinary login method after later restriction. No placeholder-email account is created. D1 enforces one owner for every `(providerId, accountId)` pair, and Telegram linking uses the constraint result rather than a race-prone read-then-insert decision.

The local public-registration path fails closed unless the browser explicitly accepts the configured current policy versions and completes Turnstile. The Worker validates the Turnstile response server-side for the exact issuer hostname and fixed registration action, returns a random short-lived one-time intent once, and stores only its SHA-256 digest. Registration exchanges the raw intent for an independent reference whose digest is bound to Better Auth's actual OAuth state digest; the callback consumes that pair atomically before Google verified-email account creation. Optional social providers cannot create public users. Only the public site key and policy version identifiers are exposed as configuration; the Turnstile secret belongs in Wrangler secrets or Secrets Store. Migration `0016` stores the server-side acceptance time and guards the version history against direct UPDATE/DELETE while its account exists; deleting the parent account removes its account-scoped history under the published privacy policy. None of these controls are active in the deployed invite-only production configuration.

## Local Restricted Account Boundary

Migration `0017` adds an independent `user.accessLevel` with `standard` and `restricted` values. Existing rows backfill to `standard`; invited and bootstrap registrations remain standard, while an uninvited public registration is persisted as restricted. `user.status` remains the lifecycle control: a restricted active user may sign in, manage ordinary account state and Passkeys, consent, and complete ordinary OIDC, whereas suspension blocks session creation.

- Restricted accounts have effective PGID platform role `user`. D1 rejects elevated stored roles, optional provider-account inserts after the initial verified Google identity, and new/updated OAuth client ownership assignments targeting inactive/restricted users. Restriction does not implicitly disable an already owned RP; client containment remains a separate administrator decision.
- Request-scoped guards re-read D1 before provider linking and every admin/developer/client-management permission check. Management/developer writes and their success audit then commit only while the same D1 actor session remains live and the account snapshot is still active, standard, and role-consistent; a changed snapshot writes neither. Existing linked providers remain valid ordinary login methods.
- Restricting an account demotes it to `user` and revokes its central sessions, access tokens, and refresh tokens. Promotion changes only access level; it does not reactivate a suspended user or restore a previous elevated role. Role assignment remains a separate hierarchy-checked operation.
- Restrict/promote and suspend/reactivate state transitions use guarded D1 batches so the state mutation and success audit either both match the same user snapshot or neither is written. Restricted-action denials expose only a user UUID and fixed surface enum in audit metadata.
- [`docs/runbooks/public-registration-abuse.md`](./docs/runbooks/public-registration-abuse.md) defines the current manual, redacted D1 evidence, initial thresholds, triage, containment, false-positive handling, and configuration rollback. It is not an external monitoring system; Preview threshold validation, operator assignment, aggregation, and alert delivery remain public-launch gates.

Production is still invite-only and has not applied `0017`, deployed this Worker, or exercised these controls in Preview/production.

## Local Mail Introspection Boundary

The only delegated introspection relationship is the fixed confidential client `pgid-mail-introspect` inspecting opaque access tokens issued to `pg72-webmail`. Authorization requires a live central session, the `email` scope, and an active user with a verified email. JWTs, refresh tokens, every other client pair, and tokens missing any required state must be reported as RFC 7662 inactive.

- Unknown, expired, revoked, disabled-target, missing-`kid`, and token-controlled JOSE failures return HTTP 200 `{"active":false}`. `token_type_hint` is only a lookup hint and cannot suppress fallback to the other supported token type. JWKS corruption, duplicate matching keys, fetch failures, and other infrastructure faults remain server errors instead of being hidden as inactive tokens.
- A successful mail response exposes only the minimal allowlist required by Dovecot. It omits `sub` and `sid`; the verified email is solely a legacy mailbox lookup value, never a PGID/RP primary key, general authorization input, or account-linking key.
- Introspection uses an IP limiter at 1200 requests per 60 seconds in namespace `1004`, plus a client-class/IP limiter at 600 requests per 60 seconds in namespace `1005`. Binding failure fails closed with 503. Cloudflare's binding is per-location and permissive/eventually consistent, so these thresholds mitigate abuse but are not an exact global security counter and do not replace client authentication or D1 revocation state.
- The service secret is returned once and stored only as a hash. On suspected compromise, disable `pgid-mail-introspect` first, rotate it, and update the managed secret store and Dovecot configuration. A disabled client cannot pass a real introspection smoke test, so re-enable it in a maintenance window, run the smoke check immediately, and re-disable and roll back if it fails. Never place the secret in source, plaintext D1, logs, documents, issues, or chat.
- Provisioning, rotation, status changes, and deletion require `clients.manage_all` for system-reserved clients, a session less than 10 minutes old, and a recent Passkey step-up timestamp on that exact D1 session. The local ceremony uses a one-time session/user-bound challenge, exact origin/RP ID, required user verification, and guarded credential counters. Production has not applied `0014` or deployed this code, so independent review, deployment, and production smoke remain rollout blockers.
- Client state mutations and their audit insert commit together in D1 before a response. The D1 `audit_event` row is the source of truth; Queue delivery is post-commit, best-effort event fan-out and must not make a committed mutation appear rolled back when delivery fails. There is no durable outbox or replayer yet, so a Queue failure before acceptance can lose fan-out while the authoritative D1 audit row remains; closing that gap stays on the Production GO gate.

This behavior is pinned by the exact-version patch `patches/@better-auth__oauth-provider@1.6.23.patch`. It keeps same-client introspection as the default and adds only an opt-in opaque-access-token authorization hook, RFC 7662 inactive handling, hint fallback, and JOSE/`kid` classification. Do not carry the patch mechanically to another provider version or use `allowUnusedPatches` to hide a mismatch. Remove it only after an audited pinned stable provider supplies equivalent behavior, a clean frozen install succeeds without the patch, and the full introspection/protocol regression suite passes.

## Wiki Build-Tool Compatibility Exception

The Wiki exact-pins `vitepress@1.6.4`. That release declares
`vite@^5.4.14`, whose entire allowed range is affected by High
`GHSA-fx2h-pf6j-xcff` / `CVE-2026-53571`. The workspace therefore applies the
single dependency-scoped override `vitepress@1.6.4>vite=6.4.3`, the first
patched Vite 6 release. This does not override the SSO application's exact
Vite 8 dependency and does not add Vite as a direct Wiki dependency.

- Exposure: the advisory requires a network-exposed Vite development server
  and Windows/NTFS path behavior. Production deploys only validated static
  VitePress output; the build validator rejects Pages Functions, `_worker.js`,
  `_routes.json`, and source maps. Local `pnpm dev:wiki` remains loopback-only
  unless an operator explicitly changes the host.
- Compatibility control: Vite 6.4.3 is outside VitePress 1.6.4's declared
  range. Every lockfile change must run a frozen install, the complete Wiki
  parser/build/link/asset/header gate, the Chrome desktop/mobile dark/light
  crawl, and `pnpm security:audit`. An audit ignore is not allowed.
- Exit condition: remove this override when an audited stable VitePress release
  used by PGID officially supports a Vite version patched for this advisory;
  exact-pin that release and rerun the same compatibility and browser gates.

## Accepted Phase 0 Finding

`GHSA-p2fr-6hmx-4528` affects `@better-auth/oauth-provider@1.6.23`. The stable `1.6.x` line has no patched release; the current fix is pre-release only.

The canonical machine-readable acceptance is
[`security/accepted-advisories.json`](./security/accepted-advisories.json). CI
requires the live `pnpm audit --json` result to match every recorded advisory
field and installed version exactly; stale, changed, expired, or unrecorded
findings fail. The maximum waiver duration is 180 days, and High/Critical
findings are never accepted by this mechanism.

- Severity: Moderate.
- Owner: PGID maintainer.
- Target date: 2026-10-16, or before full Production GO or adoption of the first
  audited stable fixed release, whichever comes first. The owner must review
  the accepted risk at that boundary even if no stable fix is available.
- Exposure: resource indicators could otherwise select an audience not bound to the original grant.
- Controls: exactly one `validAudiences` entry; the Worker rejects every `resource` parameter at `/oauth2/authorize` and `/oauth2/token`; v1 resource servers must require an exact single audience and must not use RFC 8707 resource indicators as an authorization boundary.
- Exit condition: upgrade core and all Better Auth plugins together to the first audited stable release containing the fix, run its schema migration, remove the temporary edge rejection only after protocol regression tests pass.

The accepted finding blocks general-purpose resource indicators. It does not permit ignoring future High or Critical advisories.
