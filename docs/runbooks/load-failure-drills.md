# Local Load and Failure Drills

This runbook covers bounded, source-local PGID request and regression drills.
It cannot load, modify, deploy, restore, or inject faults into Preview or
production.

## Fixed profile

`security/public-readiness-policy.json` owns the drill target and ceilings. The
committed profile is:

| Control | Value |
| --- | ---: |
| Origin | `http://127.0.0.1:5185` |
| Requests | 96 |
| Concurrency | 4 |
| Schedule rate | 12 requests/second |
| Hard duration | 10 seconds |

The profile is validated against absolute ceilings before the listener starts.
Every live request shares the hard deadline. The command accepts no target or
budget arguments.

## Coverage

The command uses fresh migrated local D1 state and performs:

- concurrent SSO workerd probes for health, discovery, invalid authorization,
  unauthorized UserInfo, and unauthorized admin access, followed by a check
  that no user, session, access-token, or refresh-token state was created;
- concurrent test-RP health and invalid-callback probes, followed by a check
  that no RP session, OAuth transaction, or logout receipt state was created;
- the existing global-logout delivery/retry regression suite;
- a fixed live-Worker profile over health, readiness, discovery, and the same
  negative auth surfaces, retaining only aggregate status and latency data;
- post-listener D1 migration-head, supported `quick_check`, foreign-key, and
  row-count manifest checks; and
- finally-block listener and temporary-state cleanup, with any cleanup failure
  recorded as a blocker.

The workerd Queue suite is synthetic. Encrypted R2 archival is
`dependency_missing` while its source slice is absent and must remain `not_run`
after source integration until a real local archive/restore exercise is added;
source presence alone never yields `passed`. Real Queue/DLQ operations also
remain an independent exercise. This command does not simulate an external
Cloudflare outage and does not justify a production fault-injection claim.

## Run

From the repository root, with Cloudflare credential variables absent, run:

```bash
pnpm public-readiness:drills:local
```

The mode-`0600` report is written to:

```text
.artifacts/public-readiness/drills-local.json
```

Each scenario contains only its fixed ID, request/status/error/timeout counts,
throughput, and aggregate p50/p95/p99/max latency. URLs, headers, cookies,
response bodies, identities, tokens, and raw errors are excluded. Early
failures still write dependencies, cleanup, fixed suite/invariant state, and a
bounded failure stage/class.

The command exits nonzero for a failed scenario, invariant, suite, cleanup, or
missing dependency. A report with `ready: true` is only a synthetic local pass.
Preview baseline selection, approved traffic budgets, actual Queue retry/DLQ
and R2 failure exercises, alert delivery, rollback, independent review, and
owner approval remain separate gates.
