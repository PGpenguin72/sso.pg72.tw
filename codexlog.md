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
