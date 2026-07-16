# Security Policy

PGID currently runs as a deployed, invite-only production beta. Existing deployment records show Copy and Link using PGID for production sign-in. Public registration remains disabled.

This deployed state is not the same as full Production GO or general-public approval. Central `sid` propagation, back-channel logout, recovery/rotation drills, independent review, and other gates below are still incomplete; no document may treat production traffic alone as proof that those controls passed.

The local `main` source now includes the narrowly scoped Mail Path A introspection prerequisite and has passed its full local typecheck, workerd, production-build, and test-RP protocol gate. It has not been deployed, the `pgid-mail-introspect` system client has not been provisioned, no remote D1 operation was performed, and the mail VPS has not been cut over. These local results must not be represented as production behavior.

## Reporting

Do not open a public issue containing secrets, tokens, personal data, or an exploit against a live PG72 service. Send a private report to the project owner with:

- affected endpoint and environment;
- minimal reproduction steps;
- expected and observed behavior;
- impact assessment;
- logs with credentials and personal data removed.

## Invite Beta Release Gate

Changes to the deployed invite beta require:

- strict TypeScript, workerd tests, production builds, dependency audit, and secret scan appropriate to the change;
- no open Critical or High finding;
- every Medium finding recorded with an owner, compensating control, and target date;
- affected Google, Passkey, OIDC negative/replay, revoke, and request-abort checks;
- an explicit rollback path and post-release smoke checks.

Passing this narrower gate permits an invite-beta release only. It does not authorize public registration or a full Production GO claim.

## Full Production GO and Public Registration Gate

Before enabling `REGISTRATION_MODE=public` or declaring full Production GO, complete and record:

- independent security review and OIDC conformance/security testing;
- DAST across auth, OIDC, admin, gateway, and logout endpoints;
- automated SAST, dependency, secret, and IaC/config scanning;
- central `sid`, replay-safe back-channel logout, retry/DLQ alerting, and RP logout verification;
- recovery-code/break-glass, signing-key rotation, D1 restore, and Queue retry/DLQ drills;
- Turnstile or equivalent bot controls, abuse response, and versioned Terms/Privacy consent;
- Passkey step-up for high-risk system-client provisioning and secret rotation; the current session-age freshness check is not reauthentication and does not satisfy this gate;
- no unresolved Critical or High finding; every accepted Medium still needs an owner, deadline, and compensating control.

The canonical checklist is [`codex.md`](./codex.md) §9.2. The deployed configuration remains `invite` until that gate passes and the owner explicitly approves and deploys the switch.

## Local Mail Introspection Boundary

The only delegated introspection relationship is the fixed confidential client `pgid-mail-introspect` inspecting opaque access tokens issued to `pg72-webmail`. Authorization requires a live central session, the `email` scope, and an active user with a verified email. JWTs, refresh tokens, every other client pair, and tokens missing any required state must be reported as RFC 7662 inactive.

- Unknown, expired, revoked, disabled-target, missing-`kid`, and token-controlled JOSE failures return HTTP 200 `{"active":false}`. `token_type_hint` is only a lookup hint and cannot suppress fallback to the other supported token type. JWKS corruption, duplicate matching keys, fetch failures, and other infrastructure faults remain server errors instead of being hidden as inactive tokens.
- A successful mail response exposes only the minimal allowlist required by Dovecot. It omits `sub` and `sid`; the verified email is solely a legacy mailbox lookup value, never a PGID/RP primary key, general authorization input, or account-linking key.
- Introspection uses an IP limiter at 1200 requests per 60 seconds in namespace `1004`, plus a client-class/IP limiter at 600 requests per 60 seconds in namespace `1005`. Binding failure fails closed with 503. Cloudflare's binding is per-location and permissive/eventually consistent, so these thresholds mitigate abuse but are not an exact global security counter and do not replace client authentication or D1 revocation state.
- The service secret is returned once and stored only as a hash. On suspected compromise, disable `pgid-mail-introspect` first, rotate it, and update the managed secret store and Dovecot configuration. A disabled client cannot pass a real introspection smoke test, so re-enable it in a maintenance window, run the smoke check immediately, and re-disable and roll back if it fails. Never place the secret in source, plaintext D1, logs, documents, issues, or chat.
- Provisioning, rotation, status changes, and deletion require `clients.manage_all` for system-reserved clients and the current session-age gate. That gate is only a compensating control; missing Passkey step-up remains a production blocker.
- Client state mutations and their audit insert commit together in D1 before a response. The D1 `audit_event` row is the source of truth; Queue delivery is post-commit, best-effort event fan-out and must not make a committed mutation appear rolled back when delivery fails. There is no durable outbox or replayer yet, so a Queue failure before acceptance can lose fan-out while the authoritative D1 audit row remains; closing that gap stays on the Production GO gate.

This behavior is pinned by the exact-version patch `patches/@better-auth__oauth-provider@1.6.23.patch`. It keeps same-client introspection as the default and adds only an opt-in opaque-access-token authorization hook, RFC 7662 inactive handling, hint fallback, and JOSE/`kid` classification. Do not carry the patch mechanically to another provider version or use `allowUnusedPatches` to hide a mismatch. Remove it only after an audited pinned stable provider supplies equivalent behavior, a clean frozen install succeeds without the patch, and the full introspection/protocol regression suite passes.

## Accepted Phase 0 Finding

`GHSA-p2fr-6hmx-4528` affects `@better-auth/oauth-provider@1.6.23`. The stable `1.6.x` line has no patched release; the current fix is pre-release only.

- Severity: Moderate.
- Owner: PGID maintainer.
- Exposure: resource indicators could otherwise select an audience not bound to the original grant.
- Controls: exactly one `validAudiences` entry; the Worker rejects every `resource` parameter at `/oauth2/authorize` and `/oauth2/token`; v1 resource servers must require an exact single audience and must not use RFC 8707 resource indicators as an authorization boundary.
- Exit condition: upgrade core and all Better Auth plugins together to the first audited stable release containing the fix, run its schema migration, remove the temporary edge rejection only after protocol regression tests pass.

The accepted finding blocks general-purpose resource indicators. It does not permit ignoring future High or Critical advisories.
