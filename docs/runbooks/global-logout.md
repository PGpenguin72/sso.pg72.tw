# Global Logout Delivery Runbook

> Status: completed local source and regression contract. Final independent
> source review is still required. This runbook does not claim that migration
> `0018`, the dedicated Queue/DLQ, any RP receiver, an external dashboard, or
> paging is deployed in Preview or production.

This runbook covers the durable OIDC back-channel logout path implemented by
PGID. The D1 session, tokens, audit event, and one delivery row per visited RP
commit before any Queue message is sent. D1 is therefore the source of truth;
Cloudflare Queues only accelerates delivery and may deliver a message more than
once.

## Runtime contract

- `rp_session_client` records the actual `(central sid, client_id)` pair only
  after a user-bound access token is issued for a still-live central session.
  Client Credentials grants never enter the ledger.
- A self-service revoke, sign-out, RP-initiated logout, administrator revoke,
  restrict, suspend, or account deletion snapshots the visited RPs into
  `logout_delivery` in the same D1 batch that revokes central state and writes
  the audit event.
- `LOGOUT_DELIVERIES` publishes to the dedicated
  `pg72-id-logout-deliveries` Queue. Its DLQ is
  `pg72-id-logout-deliveries-dlq`; it is intentionally separate from the
  security-event Queue so an older Worker cannot misinterpret the message
  format during rollback.
- A one-minute Cron re-enqueues due or expired-lease D1 rows. Queue loss alone
  therefore cannot lose durable logout work.
- Queue and operator replay surfaces use an opaque, Web Crypto-derived
  `deliveryKey`; the internal sequential D1 primary key is never exposed.
- Claiming commits an `in_flight` attempt before HTTP starts. The HTTP result
  terminalizes the attempt and delivery in one D1 batch. An expired lease first
  terminalizes its prior attempt as `lease_expired`, then retries or becomes
  dead at attempt five; a reused delivery keeps the same `jti`.
- Delivery is successful only on HTTP `200` or `204`. Timeout, network errors,
  `408`, `425`, `429`, and `5xx` retry. Every other HTTP response, including
  `201`, redirects, and other `4xx`, is permanent. Automatic delivery stops
  after five attempts with bounded backoff.
- The logout token is an EdDSA JWT signed by the same current PGID signing path
  published through JWKS. It contains `iss`, `aud`, `iat`, `exp`, `jti`, the
  OIDC back-channel logout event claim, and `sid`; it never contains `nonce`.
- An RP returns `200` or `204` after idempotently deleting every local session
  matching `sid`. Duplicate `jti` delivery must remain successful.

## Preview prerequisites

Do not bind Preview code to production data or credentials. Before a Preview
exercise, an authorized operator must provide all of the following in the
isolated Preview Cloudflare account:

1. Separate PGID and RP D1 databases with migrations applied through `0018`
   and the RP back-channel migration.
2. Separate security-event and logout-delivery Queues, with separate DLQs and
   the exact bindings in `apps/sso/wrangler.jsonc`.
3. Preview-only secrets, signing keys, domains, Google callbacks, and Rate
   Limiting namespaces.
4. One exact registered HTTPS `backchannelLogoutUri` for each participating RP.
   Wildcards, fragments, any `@`, and cross-environment endpoints are not
   accepted. Development HTTP loopback endpoints require an explicit port.
5. An RP receiver that stores central `sid`, validates the complete logout
   token contract, and deletes by `sid` in an idempotent transaction.
6. A named operator and response channel. External aggregation and paging are
   still missing from this repository and must be implemented and exercised
   before claiming operational alerting.

Existing deployment records only confirm production migrations through
`0012`. Before any production maintenance, re-check the live migration state,
run the `0015` provider-identity duplicate preflight in `codex.md`, create an
owner-controlled backup or Time Travel checkpoint, and review every pending
migration in numeric order. Applying local migrations or provisioning queues is
an owner operation, not an automated action from this repository.

## Migration `0018`

Migration `0018_global_logout.sql`:

- adds the dedicated `oauthClient.backchannelLogoutUri` column and backfills a
  valid legacy standard metadata value;
- preserves the unused pre-existing table as
  `logout_delivery_legacy_0018` instead of deleting its evidence;
- creates the visited-client ledger, durable delivery state, attempt evidence,
  opaque delivery keys, indexes, constraints, and access-token ledger trigger.

After applying it in an isolated environment, verify with read-only queries:

```sql
PRAGMA foreign_key_check;
PRAGMA integrity_check;

SELECT name, type
FROM sqlite_master
WHERE name IN (
  'rp_session_client',
  'logout_delivery',
  'logout_delivery_attempt',
  'logout_delivery_legacy_0018',
  'oauth_access_token_record_rp_visit'
)
ORDER BY name;
```

`foreign_key_check` must return no rows and `integrity_check` must return `ok`.
Re-running the migration command must report no pending migrations; do not
manually replay the SQL against a database whose migration ledger already
contains `0018`.

## Preview acceptance

Exercise the following with redacted evidence and retain the Worker version,
migration list, Queue/DLQ names, timestamps, and result counts:

1. Authorize one central session to two test RPs, confirm two ledger rows, then
   revoke that session and confirm central session/tokens disappear while two
   durable delivery rows and one success audit commit.
2. Exercise self single-session revoke, other-session revoke, all-session
   revoke, sign-out, RP-initiated logout, admin revoke, restrict, suspend, and
   account deletion. Force account-deletion outbox failure and confirm the
   actor/session snapshot, RP rows, tokens, owned clients, success audit,
   account, user, Queue dispatch, and cookie cleanup all roll back together.
3. Confirm each logout token passes signature, issuer, audience, lifetime,
   event, `sid`, `jti`, and no-`nonce` validation, and that both first and
   duplicate deliveries return `200` or `204`.
4. Reject bad issuer, audience, signature, event claim, lifetime, nonce,
   malformed form bodies, and conflicting reuse of one `jti` for another
   `sid` without deleting an RP session.
5. Simulate timeout, `408`, `425`, `429`, `5xx`, permanent `201`/`3xx`/`4xx`,
   partial Queue-send failure, lost Queue messages, HTTP success followed by
   result-persistence failure, and an expired D1 lease. Confirm `in_flight`
   evidence exists before HTTP, `jti` remains stable, every attempt becomes
   terminal, attempt five becomes `dead`, and Cron recovery is bounded.
6. Race two revocations of the same session. Confirm one central transition,
   no duplicate `(event, sid, client)` delivery, and no missing durable work.
7. Confirm Queue messages and admin replay use opaque `deliveryKey` values, and
   admin list responses omit the internal sequential ID, endpoint, `sid`,
   `jti`, token, and user identity. Confirm manual replay requires
   `users.manage`, a fresh session, and Passkey step-up.
8. Scan Worker and RP logs to confirm no logout token, authorization code,
   session ID, client secret, Passkey challenge, full email, or full IP is
   emitted.
9. Trigger the external alert path for dead deliveries and DLQ growth. Until a
   real receiver and operator acknowledgement are recorded, this acceptance
   item remains incomplete.

## Triage and replay

The source exposes a redacted operator view:

```text
GET /api/admin/logout-deliveries?status=dead&limit=50
```

The response contains an opaque `deliveryKey`, client ID, reason, status,
attempt count, replay count, a bounded error code, and timestamps. It
intentionally excludes the internal sequential primary key, endpoint snapshot,
central `sid`, `jti`, and token.

For a dead or retrying item:

1. Verify the RP deployment, exact registered endpoint, TLS, discovery/JWKS
   reachability, clock, and receiver validation logs without requesting or
   exposing the raw logout token.
2. Correct the RP or its registered endpoint. Do not edit a historical delivery
   row directly.
3. With a fresh, Passkey-stepped-up administrator session, replay:

   ```text
   POST /api/admin/logout-deliveries/{deliveryKey}/replay
   ```

4. HTTP `200` means the durable row was reset and immediately queued. HTTP
   `202` means the D1 reset and audit committed but immediate Queue send failed;
   the Cron replayer will recover it. A `202` must not be treated as rollback.
5. Confirm the replay generation produces new attempt evidence and reaches
   `delivered`, or re-enters `dead` after the bounded attempts.

Repeated delivery is expected. Never restore a revoked central session or token
to compensate for an RP receiver failure.

## Rollback

1. Keep production invite-only and stop the rollout at the single RP currently
   under Preview validation.
2. Stop new code deployment or route traffic back only to a reviewed Worker
   version compatible with the already-applied schema. Do not drop `0018`, the
   preserved legacy table, the ledger, delivery rows, or attempt evidence.
3. Because logout has a dedicated Queue, a previous Worker can continue serving
   unrelated security events without consuming the new logout message format.
   Pause the logout consumer if the rollback Worker cannot process it; retain
   D1 rows and Queue/DLQ messages for the repaired Worker.
4. Keep central sessions and tokens revoked. Rollback must never resurrect
   authentication state merely because an RP notification is delayed.
5. Record the affected opaque delivery keys, RP client IDs, first/last timestamps,
   Worker versions, migration state, Queue/DLQ depth, containment decision, and
   follow-up owner without including tokens, `sid`, secrets, or user identity.
