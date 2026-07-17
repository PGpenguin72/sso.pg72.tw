# Account Recovery Runbook

> Status: completed local source and workerd regression contract. Production
> records still show migrations through `0012`; migration `0019`, the recovery
> Rate Limiting binding, `RECOVERY_MODE=enabled`, independent review, and every
> Preview/production drill below remain unapplied. This document does not
> authorize a coding agent to deploy, inspect remote D1, or change production.

This runbook covers PGID's recovery-code and replacement-Passkey path. The
feature is independently controlled by `RECOVERY_MODE`; applying schema does
not enable it. Raw codes are user-held secrets that PGID returns once and never
stores, logs, exports, or reconstructs.

## Runtime contract

- One active generation per user contains ten `PGID-R1` codes. Each code has
  160 bits of Web Crypto entropy; D1 stores only its globally unique SHA-256
  digest. Current sets have no automatic expiry, while the schema preserves a
  nullable future-policy field.
- Issue, rotate, and revoke require an active normal session created less than
  ten minutes ago, at least one Passkey, and a recent Passkey step-up on that
  exact D1 session. The committing D1 batch repeats the live-session,
  freshness, step-up, generation, and active-set predicates.
- Recovery entry consumes its dedicated per-IP limiter before parsing or hash
  lookup. Malformed, unknown, consumed, revoked, expired, suspended, and
  competing inputs return one generic denial.
- A valid code is consumed when a ten-minute recovery session begins. Cancel or
  ceremony failure never restores it. The host-only cookie is restricted to
  `/api/recovery`; only its digest is stored, and it cannot authorize any
  normal account, admin, OIDC, consent, or token surface.
- Replacement Passkey registration uses a two-minute one-time challenge,
  exact origin/RP ID, required user verification, no attestation, bounded
  fields, and global credential-ID uniqueness.
- Completion atomically creates the replacement Passkey and success audit,
  revokes the old code set, creates the next ten hashes, removes all central
  sessions/access tokens/refresh tokens and relevant verification state, and
  creates durable logout work for visited RPs. Queue dispatch is post-commit.
  The browser receives the next raw codes once and must perform normal sign-in.
- `RECOVERY_MODE=disabled` makes both management and recovery endpoints return
  404. Existing users receive no rows merely because `0019` was applied.

## Preview prerequisites

Do not bind this source to production data, credentials, or domains during
validation. An authorized owner/operator prepares an isolated Preview
Cloudflare account with:

1. A separate PGID D1 database with reviewed migrations applied in numeric
   order through `0019`, plus separate test-RP databases through their current
   migrations.
2. Preview-only domains, Google callbacks, secrets, signing keys, Queues/DLQs,
   and all Rate Limiting namespaces. `RECOVERY_RATE_LIMITER` uses namespace
   `1006` at 10 attempts per 60 seconds; it must not reuse production state.
3. `REGISTRATION_MODE=invite` unless the separate public-registration gate is
   under test. Recovery testing does not authorize public registration.
4. `RECOVERY_MODE=disabled` for the schema and ordinary-login smoke first, then
   an owner-recorded change to `enabled` only for the isolated exercise.
5. At least two disposable users: one standard and one restricted. Each has a
   normal social login, two distinct Passkeys, and no production identity or
   personal data. Include two test RPs with validated `sid` receivers.
6. A named operator, reviewer, rollback owner, evidence location, and incident
   channel. Evidence contains versions, timestamps, counts, and bounded status
   enums only, never raw codes, cookies, challenges, credential IDs, email, IP,
   access/refresh tokens, or logout tokens.

Existing production records only confirm migration `0012`. Before any future
production maintenance, the owner must re-check remote state, run the `0015`
provider-identity and `0019` Passkey-credential duplicate preflights in
`codex.md` §§0.1-0.2, take a private backup or Time Travel checkpoint, and
review every pending migration from `0013` through `0019` in order. No step in
this runbook changes that ownership boundary.

## Migration `0019`

Migration `0019_recovery_codes.sql` creates:

- `recovery_code_set` and its one-active-set-per-user index;
- `recovery_code` with global digest uniqueness and once-only consumption;
- `recovery_session`, bound to one exact consumed code/set/user for at most ten
  minutes;
- `recovery_passkey_challenge`, one per recovery session for at most two
  minutes;
- a global unique index on `passkey.credentialID`; and
- immutability, active-owner, expiry, consumption, revoke/cascade, and
  suspended-user cleanup triggers.

After applying it in isolated Preview, use read-only checks:

```sql
PRAGMA foreign_key_check;
PRAGMA integrity_check;

SELECT name, type
FROM sqlite_master
WHERE name IN (
  'recovery_code_set',
  'recovery_code',
  'recovery_session',
  'recovery_passkey_challenge',
  'recovery_code_set_active_user_idx',
  'passkey_credential_id_unique_idx'
)
ORDER BY type, name;

SELECT COUNT(*) AS existing_user_recovery_rows
FROM recovery_code_set;
```

`foreign_key_check` returns no rows, `integrity_check` returns `ok`, all six
objects are present, and the final count is zero before a disposable user
explicitly creates codes. Re-running the migration command must report no
pending migration; never replay SQL manually against a ledger that contains
`0019`.

## Preview acceptance

Retain redacted evidence for every item:

1. With recovery disabled, confirm every management/recovery endpoint returns
   404 while Google, ordinary Passkey, OIDC authorize/token, account, and admin
   regressions remain unchanged.
2. Enable recovery. For standard and restricted active users, complete fresh
   session plus Passkey step-up and issue ten unique correctly formatted codes.
   Confirm response `no-store`, nullable expiry, exactly ten 43-character D1
   digests, no raw value at rest, and status responses that never return codes.
3. Reject missing Passkey, missing/stale/future step-up, stale/future session,
   expired normal session, suspended user, invalid Origin/media type/body, and
   an interposed state change before commit. Confirm no success audit or partial
   generation remains.
4. Rotate and revoke. Confirm old hashes and in-progress recovery principals
   cascade away, generation increases monotonically, one active set remains,
   and raw codes are visible only in the successful one-view response.
5. Exercise malformed, unknown, consumed, revoked, expired, and suspended code
   states plus simultaneous use of one valid code. Confirm identical denial
   bodies, one winner, permanent consumption, and no account/provider/email
   disclosure. Confirm limiter denial and binding failure fail closed without
   echoing input.
6. Inspect the recovery cookie attributes and hash-only D1 token. Attempt
   account, admin, consent, authorize, token, UserInfo, normal Passkey
   management, and session endpoints with only that cookie; all must remain
   unauthorized and no normal session may be created.
7. Cancel recovery and confirm the accepted code stays consumed while another
   unused code can start. Exercise recovery-session and challenge expiry, a
   second options request, malformed registration, wrong origin/RP ID, missing
   UV, duplicate credential ID, replay, and parallel completion.
8. Complete a genuine P-256 registration. Confirm one replacement Passkey,
   next-generation ten hashes, zero old recovery sessions, zero old central
   sessions/tokens, cleared verification state, one success audit, and one
   durable logout row per visited test RP. Sign in normally with the recovered
   Passkey and confirm the old sessions cannot return.
9. Force Queue send failure after commit. Central state must remain revoked and
   durable logout rows pending. Then force a core statement failure inside the
   completion batch and confirm Passkey, success audit, new codes, token/session
   revoke, and logout rows all roll back; no success cookie or Queue dispatch
   may escape.
10. Attempt to unlink the final social provider with zero unused codes and while
    recovery is disabled; both fail. With an active unused code and another
    sign-in method, it succeeds. Interpose code consumption before the DELETE
    commits and confirm the unlink loses the race. More than one social provider
    remains unaffected by this additional policy.
11. Scan D1, Worker/Queue/RP logs, browser storage, audit metadata, build output,
    and retained evidence for raw codes, recovery tokens, challenges,
    credential IDs, full email/IP, authorization codes, and access/refresh or
    logout tokens. Any match stops rollout.
12. Run the complete repository check, dependency audit, production dry-run,
    secret/config scan, independent source/security review, and desktop/mobile
    browser exercise before the Preview reviewer signs off.

## Triage

Use only redacted aggregate evidence from these event types:

```text
recovery.rate_limited
recovery.entry_denied
recovery.codes_issued
recovery.codes_revoked
recovery.started
recovery.passkey_failed
recovery.completed
```

For an unexpected increase, first confirm deployed Worker version, migration
ledger, `RECOVERY_MODE`, limiter binding health, D1 health, and Queue/DLQ state.
Do not ask a user to disclose a raw code and do not query or export token hashes
as a substitute. Suspend a user or disable recovery only through an authorized,
audited owner/operator decision; preserve existing code/audit evidence for
review.

If a user reports code exposure while still signed in, rotate or revoke the set
after a fresh session and Passkey step-up. If the user has lost every login
method and every code, there is no email merge, database reconstruction,
administrator bypass, or undocumented support override. Escalate to the owner
under a separately reviewed identity-proofing/break-glass policy.

## Rollback

1. Set `RECOVERY_MODE=disabled` in the affected environment through the
   owner-controlled configuration/deployment process. Confirm the recovery UI
   hides and endpoints return 404 while ordinary login/OIDC remains healthy.
2. Stop rollout at the single isolated Preview environment or RP under test.
   Do not enable production merely to reproduce a failure.
3. Route traffic only to a reviewed Worker version compatible with the already
   applied schema. Do not drop `0019`, active/revoked sets, consumed evidence,
   sessions, challenges, indexes, or triggers during incident rollback.
4. Keep already revoked central sessions/tokens revoked. Never restore a
   consumed code or old session to compensate for failed recovery or delayed RP
   logout delivery.
5. If completion committed but Queue dispatch failed, follow the durable
   delivery triage in [`global-logout.md`](./global-logout.md); do not replay the
   recovery transaction or expose a replacement code through operator tools.
6. Record environment, Worker version, migration state, bounded event counts,
   first/last timestamps, containment decision, reviewer, and follow-up owner.
   Exclude all credentials and user identity.

Production enablement is a separate owner decision after isolated Preview and
independent review. The safe default remains `RECOVERY_MODE=disabled`.
