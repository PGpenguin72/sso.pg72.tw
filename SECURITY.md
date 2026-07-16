# Security Policy

PGID currently runs as a deployed, invite-only production beta. Existing deployment records show Copy and Link using PGID for production sign-in. Public registration remains disabled.

This deployed state is not the same as full Production GO or general-public approval. Central `sid` propagation, back-channel logout, recovery/rotation drills, independent review, and other gates below are still incomplete; no document may treat production traffic alone as proof that those controls passed.

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
- no unresolved Critical or High finding; every accepted Medium still needs an owner, deadline, and compensating control.

The canonical checklist is [`codex.md`](./codex.md) §9.2. The deployed configuration remains `invite` until that gate passes and the owner explicitly approves and deploys the switch.

## Accepted Phase 0 Finding

`GHSA-p2fr-6hmx-4528` affects `@better-auth/oauth-provider@1.6.23`. The stable `1.6.x` line has no patched release; the current fix is pre-release only.

- Severity: Moderate.
- Owner: PGID maintainer.
- Exposure: resource indicators could otherwise select an audience not bound to the original grant.
- Controls: exactly one `validAudiences` entry; the Worker rejects every `resource` parameter at `/oauth2/authorize` and `/oauth2/token`; v1 resource servers must require an exact single audience and must not use RFC 8707 resource indicators as an authorization boundary.
- Exit condition: upgrade core and all Better Auth plugins together to the first audited stable release containing the fix, run its schema migration, remove the temporary edge rejection only after protocol regression tests pass.

The accepted finding blocks general-purpose resource indicators. It does not permit ignoring future High or Critical advisories.
