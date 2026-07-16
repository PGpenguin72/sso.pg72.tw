# Dependency patches

## `@better-auth/oauth-provider@1.6.23`

`@better-auth__oauth-provider@1.6.23.patch` is an exact-version workaround for
PGID token introspection. It makes five deliberately narrow changes:

- an opt-in hook for authorizing cross-client introspection of opaque access
  tokens; the default remains same-client only;
- RFC 7662 inactive-token handling based on `APIError.status` rather than the
  constant `APIError.name`;
- malformed JWTs, JWTs without the required PGID `kid`, and other
  token-controlled JOSE verification failures returning an inactive response;
  JWK/JWKS corruption, duplicate matching `kid` values, and fetch timeouts
  remain internal errors;
- `token_type_hint` remains a lookup hint, so a miss falls back to the other
  supported token type;
- pairwise subject resolution, when present, uses the token-owning client
  rather than the introspection client.

PGID uses the hook only for `pgid-mail-introspect` inspecting access tokens
issued to `pg72-webmail`, and requires the token to retain a live central
session, the `email` scope, and an active user with a verified email. JWT and
refresh-token delegation remain denied. Invalid client credentials remain an
HTTP 401 response at the Worker boundary.

The Worker boundary, not this dependency patch, owns request-shape checks. It
rejects duplicates only for the four single-value fields `client_id`,
`client_secret`, `token`, and `token_type_hint`; the patch must not be treated
as a general form parser or authorization bypass.

Remove this exact-version patch only after a pinned stable provider release
supplies all of the following behavior without local modification:

- cross-client opaque access-token introspection is opt-in and receives the
  token-owning client, granted scopes, resolved user, and validated live
  central session ID;
- same-client introspection remains the default, while JWT and refresh-token
  delegation stay denied;
- malformed JWTs, missing or unknown `kid` values, signature/claim failures,
  and other token-controlled JOSE errors return inactive, while duplicate
  matching keys, corrupt JWKS state, and fetch/infrastructure failures remain
  internal errors;
- an incorrect `token_type_hint` falls back to the other supported token type,
  inactive provider errors are recognized by status, and pairwise `sub` uses
  the token-owning client.

After removing the patch registration and lockfile entry, a clean frozen
install must succeed and both repository gates must pass:

```bash
pnpm install --offline --frozen-lockfile
pnpm --filter @pg72/id check
pnpm --filter @pg72/test-rp test
```

Do not carry the patch forward mechanically across provider versions, and do
not use `allowUnusedPatches` to hide a version mismatch.
