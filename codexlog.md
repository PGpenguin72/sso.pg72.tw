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
