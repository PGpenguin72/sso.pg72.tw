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

The live evidence contract is exactly six ordered scenarios with 16 requests
each:

| Scenario ID | Path | Expected status |
| --- | --- | ---: |
| `health` | `/health` | 200 |
| `readiness` | `/ready` | 200 |
| `discovery` | `/.well-known/openid-configuration` | 200 |
| `authorize_invalid` | `/oauth2/authorize` | 400 |
| `userinfo_unauthorized` | `/oauth2/userinfo` | 401 |
| `admin_unauthorized` | `/api/admin/users` | 401 |

Missing, duplicate, renamed, reordered, zero-request, count-inconsistent, or
out-of-profile scenario evidence is rejected by the report validator.

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
- post-listener complete ordered D1 migration-ledger, supported `quick_check`,
  foreign-key, and row-count manifest checks; and
- finally-block listener and temporary-state cleanup, with any cleanup failure
  recorded as a blocker.

The workerd Queue suite is synthetic. The pure archive writer and one-object
restore-verifier source are present, but the required archive runtime dependency
is absent. `encrypted_r2_archive` and the R2 invariant therefore both remain
`dependency_missing`. Once exact runtime source is integrated but its
corresponding same-run proof is absent, the dependency is
`source_present_unverified` and the R2 invariant remains `not_run`; only that
same-run archive/restore exercise can produce `verified` and `passed`. The
independently retained manifest, custody/runtime R2 integration, restore sink,
and real exercise are still missing. Real Queue/DLQ operations also remain an
independent exercise. This command does not simulate an external Cloudflare
outage and does not justify a production fault-injection claim.

## Run

Run from a clean Git worktree at an exact commit. Tracked changes, untracked
files, and unavailable Git attribution fail before setup; ignored report
artifacts do not. The report is emitted only if the final source check still
finds the same clean nonzero commit. From the repository root, with Cloudflare
credential variables absent, run:

```bash
pnpm public-readiness:drills:local
```

The mode-`0600` report is written to:

```text
.artifacts/public-readiness/drills-local.json
```

Each scenario contains only its fixed ID, exact request/status/error/timeout
counts, bounded throughput, and ordered aggregate p50/p95/p99/max latency.
URLs, headers, cookies, response bodies, identities, tokens, and raw errors are
excluded. The schema-version-2 report records the exact clean source commit;
Git failure is explicit as `unavailable` with a null commit. Early failures
write no scenario results and still include dependencies, cleanup, fixed
suite/invariant state, and a bounded failure stage/class.

The command exits nonzero for a failed scenario, invariant, suite, cleanup,
source-attribution check, or dependency that is not `verified`. Exact source
presence alone produces `source_present_unverified`; only its corresponding
same-run exercise can produce `verified`. The global-logout exercise also
requires the exact JSON test report to contain all 25 passed assertions and no
failed/skipped/pending/todo result. A report with `ready: true` is only a
synthetic local pass. Preview baseline selection, approved traffic budgets,
actual Queue retry/DLQ and R2 failure exercises, alert delivery, rollback,
independent review, and owner approval remain separate gates.
