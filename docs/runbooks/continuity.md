# Local Identity Continuity Verification

This runbook covers the source-local, synthetic PGID continuity command. It
does not target Preview or production, does not read Cloudflare credentials,
and does not establish Production GO.

## Scope

The command creates two isolated temporary D1 projects. It then:

1. records the exact clean Git commit, then runs the focused SSO,
   global-logout, and test-RP workerd continuity suites;
2. applies every integrated migration to the source database;
3. creates synthetic users, sessions, consent, client, Passkey, visited-client,
   and overlapping signing-key records using ephemeral Web Crypto material;
4. exports D1 and restores the SQL into a fresh database;
5. requires the complete ordered D1 migration ledger (count, head, ordered-name
   digest, and every source/D1 row), exact schema hash, row-count, D1-supported
   `quick_check`, foreign-key, and allowlisted record equivalence;
6. starts the restored Worker on the policy-owned literal loopback origin and
   verifies discovery, live/expired sessions, a real P-256 Passkey assertion
   and counter advance, signing-key decryption, overlap, and retirement; and
7. stops the listener and removes the temporary SQL, secrets, and D1 state.

All identities and key material are synthetic. The generated `.dev.vars`, seed
SQL, export, and local state are mode `0600` or held below a mode `0700`
temporary directory and are deleted even on failure.

## Run

Prerequisites are the repository's pinned Node, pnpm, Wrangler, installed
dependencies, and a clean Git worktree at an exact 40-character commit. Tracked
changes, untracked files, or an unavailable Git command block the run before
temporary state is created. Ignored `.artifacts/` reports do not dirty the
source attribution. The source is checked again before reporting and must still
be the same clean nonzero commit. From the repository root, with Cloudflare
credential variables absent, run:

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

The schema-version-2 report contains only the exact source commit and explicit
`clean`/`dirty`/`unavailable` source state, allowlisted booleans, aggregate row
counts, hashes, the migration-ledger summary, tool versions, dependency status,
cleanup status, and a bounded failure stage/class. It never contains a token,
code, cookie, challenge, private key, client secret, response body, full email,
IP address, or raw command error. Git failure uses `sourceCommit: null`; it is
never replaced by a zero digest.

Exit status is nonzero when source attribution, a local invariant, or cleanup
fails, or any required dependency is not `verified`. Dependency evidence has
four exact states: `dependency_missing`, `source_invalid`,
`source_present_unverified`, and `verified`. Exact nonempty source with its
required content is necessary but insufficient; only the corresponding
opaque execution proof produced by its fixed check in this same process can
promote it to `verified`; caller-provided dependency names are rejected. Empty,
truncated, lookalike, malformed, or comment-only configuration cannot be
promoted. The integrated global-logout proof requires the exact Vitest file and
suite to report 25 passed assertions with zero failed, skipped, pending, or todo
tests; exit status alone is insufficient. Both SSO execution proofs bind the
exact tracked `apps/sso` path set and regular-file bytes, together with root
manifest, lockfile, workspace policy, and package patches, before execution,
after execution, and again at proof promotion. Recovery uses the exact recovery
Vitest file and requires 4 suites and 20 passed assertions across the three
fixed recovery groups. Release automation uses an exact Node test event stream
and requires all 90 tests from the nine fixed security test files to pass with
zero failed, cancelled, skipped, or todo results. Observability migration `0020`
is now source-present, but without an evaluator/delivery same-run proof it must
remain `source_present_unverified`; encrypted R2 archive integration remains
missing. Both stay fail-closed until their executions are integrated and
reviewed.

The repository-level public-readiness unit runner fixes Node test-file
concurrency to one. Its proof-drift regressions briefly mutate and restore an
exact tracked Worker file inside `finally` to prove that an already-created
opaque proof cannot survive runtime drift; serial execution prevents any other
source-state test from observing that deliberate dirty window.

`ready: true` requires a clean attributed commit, every exact local invariant,
successful cleanup, and all five dependency contracts verified by the same
run. It means only that this synthetic local command passed. It is not evidence
that a Preview/production migration, backup, secret, Queue, R2 object, alert,
or live RP was exercised.

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
