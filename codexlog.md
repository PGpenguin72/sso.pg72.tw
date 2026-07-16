# Codex Work Log

## 2026-07-16 16:34 CST - Passkey step-up design complete

- Created isolated worktree `/private/tmp/codex-passkey-step-up` on
  `codex/passkey-step-up` from local `main` at `2cf7594`.
- Read the canonical project rules and current Worker, Better Auth Passkey
  plugin, D1 schema, client-mutation routes, account-center UI, and workerd
  test helpers. No remote, deployment, production, or secret-store operation
  was run.
- Confirmed every high-risk OAuth client mutation currently uses the shared
  fresh-session gate: generic create, trust metadata edit, secret rotation,
  status change, delete, and mail introspector provisioning.
- Chosen design: use direct, exact-version SimpleWebAuthn browser/server
  dependencies for a PGID-owned assertion ceremony. Better Auth 1.6.23's
  authentication endpoint creates a new login session and verifies with
  `requireUserVerification: false`, so it is not suitable for step-up. No
  Better Auth patch is required.
- The ceremony will require user verification, exact configured origin/RP ID,
  an allowlist containing only the current user's credentials, a short-lived
  one-time D1 challenge bound to both session and user, atomic challenge
  consumption, counter update, and a D1-backed session step-up timestamp.
- High-risk client mutations will require both the existing fresh-session
  condition and a recent Passkey step-up. The maximum step-up age will be
  runtime-configured with a bounded ten-minute default.
- There is no missing-Passkey bypass, including for bootadmin. First bootstrap
  uses the existing Google sign-in to obtain a fresh session, enrolls a
  Passkey through the normal account center, then performs step-up. This keeps
  bootstrap usable without weakening the high-risk gate.

## 2026-07-16 16:43 CST - Worker and D1 implementation

- Added migration `0014_passkey_step_up.sql`: a nullable D1-backed timestamp on
  each Better Auth session plus a short-lived challenge table with session and
  user foreign keys, one outstanding challenge per session, and expiry index.
- Added PGID-owned challenge and verification endpoints. Assertions use
  SimpleWebAuthn 13.3.x with required user verification, exact configured
  origin/RP ID, the current user's credential allowlist, bounded request data,
  atomic `DELETE ... RETURNING` challenge consumption, and guarded authenticator
  counter updates.
- Successful verification writes the session timestamp and success audit in
  one D1 batch before responding. Failed/replayed/cross-session assertions are
  denied with redacted errors and audit reason enums; no challenge, credential
  public key, assertion, token, session token, or secret is logged.
- Added a bounded runtime setting `PASSKEY_STEP_UP_MAX_AGE_SECONDS` (60-600,
  configured to 600) and regenerated local Wrangler binding types. All six
  existing fresh-gated client mutation routes now require both freshness and
  the D1 step-up state.
- Declared the already-locked SimpleWebAuthn browser/server versions as exact
  direct dependencies. Better Auth packages remain exact and unchanged at
  1.6.23; no package patch was added.
- Verification so far: production build and Wrangler type generation passed;
  `pnpm --filter @pg72/id typecheck` passed. Behavior tests are intentionally
  the next stage and have not yet been claimed as passing.

## 2026-07-16 16:47 CST - Account-center integration

- Added a pre-mutation Passkey step-up flow to all five OAuth client actions
  exposed by the React account center: create, trust edit, secret rotation,
  status change, and delete.
- The UI first asks the Worker for a challenge. A still-valid D1 step-up skips
  another prompt; otherwise `@simplewebauthn/browser` opens the native
  credential prompt and the client mutation is sent only after verification.
- Missing enrollment, stale login sessions, cancellation, expired/replayed
  challenges, and assertion failure stay fail-closed and produce actionable
  errors. No fallback authentication method or client-side timestamp is used.
- Added self-security-activity labels for successful and denied step-up events.
- Verification: `pnpm --filter @pg72/id typecheck` and
  `pnpm --filter @pg72/id build` both passed. The build emitted only the
  expected local warning that required production secret names have no local
  values; no secret value was read or printed.

## 2026-07-16 16:56 CST - Workerd security regression coverage

- Added a real WebAuthn test authenticator: workerd generates a P-256 key pair,
  stores its COSE public key, constructs authenticator/client data, signs the
  assertion, and sends the DER signature through the production Worker route.
  The SimpleWebAuthn verifier is not mocked.
- Added seven focused cases: missing Passkey/no bootadmin bypass, no step-up
  gate, successful assertion plus D1 timestamp/counter/audit and client
  mutation, challenge replay, cross-session challenge use, expired step-up,
  and missing authenticator user verification.
- Existing client-mutation tests now opt into an explicit test-only stepped-up
  fixture. The helper default remains no Passkey/no step-up, so negative tests
  cannot be accidentally bypassed by a global fixture default.
- The first worktree run lacked ignored `.dev.vars`, producing unrelated
  missing-binding failures. No private file was read or copied. Tests were
  rerun with explicit, non-functional vitest-only placeholders and localhost
  configuration.
- Verification: `pnpm --filter @pg72/id typecheck` passed; the complete
  workerd run passed 173/173 tests in 14 files. This also validates D1 support
  for the atomic `DELETE ... RETURNING` challenge-consumption statement.

## 2026-07-16 17:17 CST - Passkey negative and consistency gates complete

- Corrected the enrollment regression to exercise the effective bootstrap
  administrator and explicitly proved there is no bootadmin bypass.
- Expanded the real P-256 ceremony suite to 17 tests. It now covers wrong
  assertion origin, wrong RP ID hash, expired challenge, unknown versus
  another user's credential, exact request Origin, the 16 KiB body limit,
  every one of the six client mutation routes, and redacted audit metadata.
- Hardened finalization against concurrent observation: the credential counter
  is first advanced with a guarded CAS. A transactional D1 batch then inserts
  a success audit guarded by the live session and new counter before updating
  the session timestamp; the timestamp statement requires that exact audit
  event. Zero-change guards therefore never expose a valid timestamp.
- SQLite trigger fault injection fixes D1 behavior in regression coverage:
  counter conflicts write no timestamp, session disappearance leaves no
  timestamp or success audit, a thrown audit insert rolls back its batch, and
  an ignored audit insert cannot unlock the session. The one-time challenge
  remains consumed and an advanced authenticator counter is retained on later
  failure as the fail-closed anti-replay tradeoff.
- Verification with explicit non-secret local placeholders:
  `pnpm --filter @pg72/id typecheck` passed and the complete workerd suite
  passed 183/183 tests in 14 files. Documentation, standalone migration replay,
  and the final required `check`/RP gates remain pending.

## 2026-07-16 17:21 CST - Clean-worktree migration and RP prerequisites

- Applied migrations `0001` through `0014` in order to a newly created,
  isolated local D1 persistence directory with Wrangler. All 14 migrations
  completed successfully; no remote D1 or production command was used.
- The required test-RP run exposed a pre-existing clean-worktree mismatch:
  `apps/test-rp/wrangler.jsonc` supplied `ENVIRONMENT=local`, while the runtime
  accepts only `development`, `preview`, or `production`. A private `.dev.vars`
  file was not read or copied.
- Changed the checked-in local test-RP setting to `development`, matching the
  runtime contract. `pnpm --filter @pg72/test-rp test` then passed 4/4 tests.

## 2026-07-16 17:28 CST - Transactional orphan-audit cleanup

- Applied the independent review follow-up to the finalization batch. The
  timestamp statement now rechecks the same passkey id, user, and advanced
  counter in addition to requiring the exact success audit event.
- Added a third statement to that same D1 transaction: it deletes the exact
  success audit whenever the corresponding session/user timestamp was not
  written. Normal success is audit/timestamp/cleanup changes `[1,1,0]`; an
  ignored audit is `[0,0,0]`; a failed timestamp removes its audit before the
  transaction commits. No post-commit cleanup is required for correctness.
- Strengthened counter-conflict, session-disappearance, audit-abort, and
  audit-ignore tests to attempt a client creation afterward. Every path proves
  there is no valid timestamp, no success audit, and no mutation unlock.
- The focused real-assertion Passkey suite passed 17/17 after this change. The
  full final gate is still pending.

## 2026-07-16 17:31 CST - Test-RP type generation made hermetic

- The optional test-RP `check` initially lacked its ignored generated Env
  declarations in the clean worktree. Running the existing `cf-typegen` then
  exposed Wrangler's strict literal-var inference: `ENVIRONMENT` became only
  `"development"`, making the runtime production guard a TypeScript error.
- Updated the test-RP type-generation script to use
  `wrangler types --strict-vars false`, matching the established SSO script.
  The generated file remains ignored.
- After regeneration, test-RP typecheck and Wrangler dry-run build passed. The
  required test-RP protocol suite had already passed 4/4.

## 2026-07-16 17:34 CST - Canonical and operator documentation synchronized

- Updated `CLAUDE.md`, `codex.md`, `SECURITY.md`, `README.md`, and the current
  header/runbook in `handoff.md` to distinguish completed local implementation
  from production, which remains at migration `0012` and lacks this Worker,
  independent review, and ceremony smoke testing.
- Documented challenge/verify requests, exact Origin/RP ID, required UV,
  session/user binding, two-minute one-time challenges, the bounded 60-600
  second step-up window, counter/audit/timestamp ordering, generic failures,
  and the no-bootadmin-bypass policy in the API reference and wiki.
- Corrected recovery wording: the runtime has no bypass, but it also has no
  self-service recovery/break-glass flow when Google and every Passkey are
  lost. That design, review, and drill remain a full Production GO gate.
- Updated Mail Path A and Roundcube operator material for ordered `0013` then
  `0014` rollout, deployment/review gates, provisioning, and rollback.
- `git diff --check`, changed-document relative-link validation, wiki SUMMARY
  target validation, heading review, and stale-current-language searches pass.
