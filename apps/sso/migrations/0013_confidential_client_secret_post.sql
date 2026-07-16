-- Record the token endpoint authentication method used by PGID confidential
-- clients. Better Auth 1.6.23 still accepts legacy Basic requests at runtime,
-- but its Basic parser does not form-url-decode RFC 6749 client credentials.
-- Existing clients therefore move to form-body client_secret_post without
-- rotating secrets or changing grants.
UPDATE oauthClient
SET tokenEndpointAuthMethod = 'client_secret_post',
    updatedAt = datetime('now')
WHERE COALESCE(public, 0) = 0
  AND clientSecret IS NOT NULL
  AND length(trim(clientSecret)) > 0
  AND tokenEndpointAuthMethod IS NOT 'client_secret_post';
