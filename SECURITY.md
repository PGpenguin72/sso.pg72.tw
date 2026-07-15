# Security Policy

PGID is in Phase 0 and is not approved for production identity traffic yet.

## Reporting

Do not open a public issue containing secrets, tokens, personal data, or an exploit against a live PG72 service. Send a private report to the project owner with:

- affected endpoint and environment;
- minimal reproduction steps;
- expected and observed behavior;
- impact assessment;
- logs with credentials and personal data removed.

## Release Gate

A production release requires:

- strict TypeScript, workerd tests, production builds, dependency audit, and secret scan;
- no open Critical or High finding;
- every Medium finding recorded with an owner, compensating control, and target date;
- Google, Passkey, OIDC negative/replay, revoke, key rotation, backup restore, and request-abort checks;
- an independent review before public registration is enabled.

## Accepted Phase 0 Finding

`GHSA-p2fr-6hmx-4528` affects `@better-auth/oauth-provider@1.6.23`. The stable `1.6.x` line has no patched release; the current fix is pre-release only.

- Severity: Moderate.
- Owner: PGID maintainer.
- Exposure: resource indicators could otherwise select an audience not bound to the original grant.
- Controls: exactly one `validAudiences` entry; the Worker rejects every `resource` parameter at `/oauth2/authorize` and `/oauth2/token`; v1 resource servers must require an exact single audience and must not use RFC 8707 resource indicators as an authorization boundary.
- Exit condition: upgrade core and all Better Auth plugins together to the first audited stable release containing the fix, run its schema migration, remove the temporary edge rejection only after protocol regression tests pass.

The accepted finding blocks general-purpose resource indicators. It does not permit ignoring future High or Critical advisories.
