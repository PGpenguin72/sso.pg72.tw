# Public Registration Abuse Response Runbook

> Status: local-source operational prerequisite; not deployed
> Scope: PGID public-registration signals and account containment
> Production remains `REGISTRATION_MODE=invite`

This runbook defines the evidence, thresholds, and operator actions available in
the repository today. It does not claim that an external dashboard, paging
integration, SIEM, or automatic suspension pipeline exists. Until those are
implemented and validated in isolated Preview, an authorized operator performs
the read-only checks below and records the review window and outcome privately.

## 1. Safety Boundaries

- Only an authorized owner/operator may inspect remote D1 or change account or
  deployment state. Coding agents do not run remote D1, deploy, or switch
  registration mode.
- Start with aggregate counts and immutable user IDs. Do not export full email,
  IP, token, authorization code, provider credential, or Passkey challenge.
- Crossing a review threshold starts triage. It does not automatically prove
  abuse and must not automatically suspend an account.
- `user.status` and `user.accessLevel` are separate controls:
  `suspended` blocks login; `restricted` keeps ordinary login, account access,
  Passkey, and OIDC usable while blocking provider linking and every
  developer/admin/client-management surface.
- Production stays invite-only until every gate in `codex.md` section 9.2 is
  complete and the owner explicitly approves and deploys the switch.

## 2. Evidence Available Today

| Evidence | Source | Redacted content |
| --- | --- | --- |
| Registration budget exhausted | `audit_event.event_type = 'registration.rate_limited'` | No email or IP |
| Registration rejected | `registration.denied` | Provider/reason enums only |
| Restricted sensitive action blocked | `account.restricted_action_denied` | User UUID and fixed `surface` enum |
| Account containment / release | `user.access_restricted`, `user.access_promoted`, `user.suspended`, `user.reactivated` | Actor/subject UUIDs and state enums |
| New public-account volume | `user.created` with metadata `accessLevel=restricted` | Immutable aggregate count; no email required |

The Workers Rate Limiting bindings still return `429` at other auth/admin
surfaces, but the current Worker does not persist every such rejection as an
audit event. Cloudflare's rate-limit binding is per-location and
permissive/eventually consistent, so neither a binding counter nor the D1
events above are exact global quotas. External aggregation and alert delivery
remain a public-launch gate.

The committed local/production-shaped limits are bounded as follows:

| Binding | Current budget | Restricted-related coverage |
| --- | --- | --- |
| `REGISTRATION_RATE_LIMITER` | 5 requests per IP per 60 seconds | New-account authorization and unmatched Telegram enrollment |
| `AUTH_RATE_LIMITER` | 30 requests per IP per 60 seconds | Sensitive auth paths including `/link-social`; Telegram uses a `tg:<ip>` key |
| `ADMIN_RATE_LIMITER` | 20 requests per user per 60 seconds | Admin/client permission checks; consumed before a restricted denial audit |

These limits reduce write amplification and repeated sensitive attempts. They
are not identity proof, exact distributed counters, or substitutes for the D1
state/permission checks.

## 3. Initial Review Thresholds

These are conservative starting thresholds for isolated Preview and the first
approved public window. The owner may revise them only after recording the
observed baseline, date, reason, and replacement values.

| Signal | Review threshold | Critical threshold |
| --- | --- | --- |
| `registration.rate_limited` | 10 events in 15 minutes | 40 events in 60 minutes |
| `registration.denied` | 25 events in 15 minutes | 100 events in 60 minutes |
| New `restricted` users | 20 users in 15 minutes | 80 users in 60 minutes |
| Restricted denials for one `subject_id` | 5 events in 15 minutes | 20 events in 60 minutes, or at least two distinct sensitive surfaces |

Open an incident and prepare the registration-mode rollback when either:

1. any two aggregate critical thresholds are crossed in the same 60-minute
   window; or
2. `registration.rate_limited` crosses its review threshold in two consecutive
   15-minute windows and the activity is not an approved test or launch event.

Do not suspend an account from an aggregate threshold alone. Account suspension
requires account-level evidence described in section 5.

## 4. Read-Only Triage

Run these statements only through owner-approved D1 tooling against the intended
environment. Keep results in the private incident record.

### 4.1 Fifteen-minute event summary

```sql
SELECT event_type, outcome, COUNT(*) AS events
FROM audit_event
WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-15 minutes')
  AND event_type IN (
    'registration.rate_limited',
    'registration.denied',
    'account.restricted_action_denied'
  )
GROUP BY event_type, outcome
ORDER BY event_type, outcome;
```

### 4.2 New restricted-account volume

```sql
SELECT COUNT(*) AS restricted_users
FROM audit_event
WHERE event_type = 'user.created'
  AND json_extract(metadata_json, '$.accessLevel') = 'restricted'
  AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-15 minutes');
```

### 4.3 Repeated restricted actions without PII

```sql
SELECT subject_id,
       COUNT(*) AS denied_actions,
       COUNT(DISTINCT json_extract(metadata_json, '$.surface')) AS surfaces
FROM audit_event
WHERE event_type = 'account.restricted_action_denied'
  AND subject_id IS NOT NULL
  AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-60 minutes')
GROUP BY subject_id
HAVING COUNT(*) >= 5
ORDER BY denied_actions DESC, subject_id;
```

### 4.4 Containment history for one user UUID

```sql
SELECT id, event_type, actor_user_id, subject_id, outcome,
       metadata_json, occurred_at
FROM audit_event
WHERE subject_id = ?
  AND event_type IN (
    'account.restricted_action_denied',
    'user.access_restricted',
    'user.access_promoted',
    'user.suspended',
    'user.reactivated',
    'user.role_changed'
  )
ORDER BY occurred_at DESC, id DESC
LIMIT 100;
```

For each review:

1. Record environment, UTC window, query version, aggregate counts, and whether
   the window contains an approved test or launch.
2. Confirm the deployed registration mode, Worker version, and applied migration
   state before attributing behavior to this local source.
3. Use the admin UI's `restricted`/`standard` filter and user UUID only when an
   account-level decision is required.
4. Check whether events span multiple fixed surfaces or continue across windows.
5. Choose the least-privilege action in section 5 and record the reason without
   copying PII into the audit metadata or incident title.

## 5. Account Decisions

| Evidence | Action |
| --- | --- |
| Threshold crossed but explained by an approved test, retry storm, or launch traffic | Record false positive; leave account state unchanged |
| New public account with no account-level abuse | Keep `restricted`; ordinary login and OIDC remain available |
| Standard account shows credible attempts to use sensitive PGID management surfaces, but continued ordinary login is acceptable | Restrict it; this demotes the platform role to `user` and revokes central sessions/tokens |
| Repeated restricted denials reach the critical threshold and span two surfaces, continue after owner contact, or correlate with a compromise report | Suspend it; do not promote as part of incident handling |
| Legitimate restricted user has completed the owner's approval process and has no unresolved abuse evidence | Promote to `standard`; assign any elevated role separately |
| A prior suspension is confirmed false positive or the incident is resolved | Reactivate separately; promotion and role assignment remain separate decisions |

The admin API operations are exact same-origin authenticated operations:

| Operation | Endpoint/body | Effect |
| --- | --- | --- |
| Restrict | `POST /api/admin/users/:id/access` with `{"restricted":true}` | Set restricted, role `user`, revoke sessions/access tokens/refresh tokens, commit success audit atomically |
| Promote | Same endpoint with `{"restricted":false}` | Set standard; do not reactivate and do not restore an old elevated role |
| Suspend | `POST /api/admin/users/:id/status` with `{"suspended":true}` | Block new login and revoke sessions/tokens, commit success audit atomically |
| Reactivate | Same endpoint with `{"suspended":false}` | Restore login eligibility; no session or role is restored |
| Assign role | `POST /api/admin/users/:id/role` | Separate hierarchy-checked action; restricted targets cannot receive elevated roles |

An admin cannot modify itself, the bootstrap administrator, or a peer admin's
role/access level. Only the bootstrap administrator may demote/restrict another
admin. Restricting an owner blocks client management but does not silently
disable an already owned RP; if the incident involves that RP, an authorized
administrator decides its status and token containment separately. Never bypass
these rules with an ad hoc D1 write during routine response.

Every management/developer mutation revalidates the actor's live session and
active, `standard`, permission-relevant D1 snapshot in the same batch as the
mutation and success audit. If the actor or target snapshot changed after the initial request guard,
the API returns a state conflict and commits neither the mutation nor a success
audit. Repeating an already-completed access/status transition is also a no-op
conflict rather than a second success event.

## 6. False Positives and Appeals

Before promotion or reactivation, require all of the following:

- an owner-approved request tied to the immutable PGID user UUID;
- confirmation that the account still controls an allowed login method;
- review of the bounded audit window for unresolved multi-surface denials;
- a recorded decision on access level, lifecycle status, and platform role as
  three separate fields.

Promotion changes only `accessLevel`. Reactivation changes only `status`.
Neither operation restores revoked sessions/tokens, and promotion never restores
the previous developer/admin role. This separation is deliberate protection
against an accidental privilege rebound.

## 7. Public-Mode Rollback

The primary rollback is configuration, not a destructive schema downgrade:

1. The owner changes `REGISTRATION_MODE` back to `invite` through the reviewed
   deployment process. Do not use a coding-agent session for this action.
2. Keep migration `0017` and every existing `accessLevel` value. Do not drop the
   column, triggers, restricted accounts, or audit rows.
3. Do not deploy a pre-`0017` Worker over a database using `0017`; provider-link
   and request-guard behavior would no longer match the schema. Use a reviewed
   forward fix or a version that retains the restricted-account contract.
4. Verify that new uninvited registration is rejected, invited/existing users
   can sign in, restricted users can complete ordinary OIDC, and restricted
   users still cannot link providers or reach admin/client management.
5. Verify the most recent restrict/promote/suspend audit rows and preserve the
   private incident timeline. Do not bulk-promote or delete accounts as part of
   rollback.

Switching back to invite mode stops new public creation; it does not suspend
existing users or invalidate ordinary RP sessions by itself. Apply account-level
containment only where the evidence supports it.

## 8. Exit Criteria for Public Launch

This runbook is a repository prerequisite, not proof of operational readiness.
Before public launch, the owner must still:

- validate and tune these thresholds in isolated Preview under approved load;
- assign an accountable operator and response channel;
- implement and test external aggregation/alert delivery for the signals;
- complete the independent security, DAST/SAST/config, recovery, load, Queue,
  logout, Turnstile/legal, and production smoke gates in `codex.md` section 9.2;
- record explicit approval before deploying `REGISTRATION_MODE=public`.
