# Dependency patches

## `@better-auth/oauth-provider@1.6.23`

`@better-auth__oauth-provider@1.6.23.patch` is an exact-version workaround for
PGID token introspection. It makes four deliberately narrow changes:

- an opt-in hook for authorizing cross-client introspection of opaque access
  tokens; the default remains same-client only;
- RFC 7662 inactive-token handling based on `APIError.status` rather than the
  constant `APIError.name`;
- malformed JWTs, JWTs without the required PGID `kid`, and other
  token-controlled JOSE verification failures returning an inactive response;
  JWK/JWKS corruption, duplicate matching `kid` values, and fetch timeouts
  remain internal errors;
- `token_type_hint` remains a lookup hint, so a miss falls back to the other
  supported token type.

PGID uses the hook only for `pgid-mail-introspect` inspecting access tokens
issued to `pg72-webmail`, and requires the token to retain a live central
session, the `email` scope, and an active user with a verified email. JWT and
refresh-token delegation remain denied. Invalid client credentials remain an
HTTP 401 response at the Worker boundary.

The Worker boundary, not this dependency patch, owns request-shape checks. It
rejects duplicates only for the four single-value fields `client_id`,
`client_secret`, `token`, and `token_type_hint`; the patch must not be treated
as a general form parser or authorization bypass.

Remove this patch only after a pinned stable provider release supplies
equivalent behavior, a clean frozen install succeeds without it, and the full
PGID introspection regression suite passes. Do not carry it forward
mechanically across provider versions, and do not use `allowUnusedPatches` to
hide a version mismatch.
