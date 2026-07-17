# Local Identity Continuity Verification

This runbook covers the source-local, synthetic PGID continuity command. It
does not target Preview or production, does not read Cloudflare credentials,
and does not establish Production GO.

## Scope

The command creates two isolated temporary D1 projects. It then:

1. runs the focused SSO and test-RP workerd continuity suites;
2. applies every integrated migration to the source database;
3. creates synthetic users, sessions, consent, client, Passkey, visited-client,
   and overlapping signing-key records using ephemeral Web Crypto material;
4. exports D1 and restores the SQL into a fresh database;
5. requires exact schema hash, migration head, row-count, D1-supported
   `quick_check`, foreign-key, and allowlisted record equivalence;
6. starts the restored Worker on the policy-owned literal loopback origin and
   verifies discovery, live/expired sessions, a real P-256 Passkey assertion
   and counter advance, signing-key decryption, overlap, and retirement; and
7. stops the listener and removes the temporary SQL, secrets, and D1 state.

All identities and key material are synthetic. The generated `.dev.vars`, seed
SQL, export, and local state are mode `0600` or held below a mode `0700`
temporary directory and are deleted even on failure.

## Run

Prerequisites are the repository's pinned Node, pnpm, Wrangler, and installed
dependencies. From the repository root, with Cloudflare credential variables
absent, run:

```bash
pnpm public-readiness:continuity:local
```

The command accepts no arguments. Its target is fixed by
`security/public-readiness-policy.json` to `http://127.0.0.1:5183`. Preview,
DNS hostnames, caller-selected origins, remote D1, and production are denied
before work starts.

## Result

The mode-`0600` machine report is written to:

```text
.artifacts/public-readiness/continuity-local.json
```

The report contains only allowlisted booleans, aggregate row counts, hashes,
tool versions, dependency status, cleanup status, and a bounded failure
stage/class. It never contains a token, code, cookie, challenge, private key,
client secret, response body, full email, IP address, or raw command error.

Exit status is nonzero when a local invariant fails, cleanup is incomplete, or
any required source dependency is absent. In particular, the report records
`dependency_missing` for missing recovery migration `0019`, observability
migration `0020`, encrypted R2 archive integration, or release automation.
That is the expected fail-closed result until those independently owned slices
are integrated and reviewed.

`ready: true` means only that this synthetic local command and its source
dependencies passed. It is not evidence that a Preview/production migration,
backup, secret, Queue, R2 object, alert, or live RP was exercised.

## Failure handling

- Read only `failure.stage`, `failure.class`, `dependencies`, and `cleanup` from
  the report. Raw Wrangler output is intentionally not persisted.
- A failed cleanup is a blocker. Confirm no process owns port `5183` before a
  later retry.
- Do not reuse an export or temporary state from a failed run. The command must
  create a fresh source and restore pair on every attempt.
- Do not add a remote flag, Cloudflare credential, configurable origin, or
  production exception to diagnose a local failure.

After a synthetic pass, the remaining rollout work is still the independently
reviewed Preview backup/restore, signing-key rotation, recovery, Queue/DLQ, R2,
alert-delivery, rollback, and owner-approved production gates in `codex.md`
section 9.2.
