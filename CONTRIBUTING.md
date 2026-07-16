# Contributing

Keep changes focused and treat PGID as security-sensitive authentication code.

## Set Up and Verify

Follow the [local setup instructions](./README.md#local-setup), then run the
canonical repository gate before opening a pull request:

```bash
pnpm check
pnpm security:check
pnpm dast:local
```

The security gate includes runtime, build, and development dependencies and
requires every observed advisory to match the expiring machine-readable record.
The DAST command is loopback-only and uses temporary synthetic D1 state. See the
[release-security runbook](./docs/runbooks/release-security.md) for gate scope,
artifacts, tool fallbacks, and the separately protected Preview workflow.

The Wiki uses the [workspace settings](./README.md#workspace) as the single
source for its local and Cloudflare Pages build configuration; do not duplicate
that settings table here. `wiki/README.md` maps to `/`, while
`wiki/SUMMARY.md` drives navigation and the content inventory. The root
`pnpm check` gate validates these relationships.

If a change affects protocol behavior, endpoints, claims, or parameters, update
[`docs/api/PGID-integration.md`](./docs/api/PGID-integration.md) and the relevant
`wiki/` pages in the same pull request. Keep user documentation in sync with
workflow changes. Architecture and security decisions remain canonical in
[`codex.md`](./codex.md).

## Protect Sensitive Systems and Data

- Never commit secrets, credentials, tokens, authorization codes, session IDs,
  personal data, production database exports, private keys, or `.dev.vars`.
- Do not deploy, run remote D1 commands, or otherwise change production or
  remote Cloudflare state as part of a contribution. Pull requests must be
  verifiable against local source.
- Do not disclose a live vulnerability in a public issue or pull request.
  Follow [`SECURITY.md`](./SECURITY.md) for private reporting instructions.
