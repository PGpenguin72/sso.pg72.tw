UPDATE oauthClient
SET scopes = '["openid","profile","email","offline_access"]',
    grantTypes = '["authorization_code","refresh_token"]',
    skipConsent = 0,
    requirePKCE = 1,
    public = 0,
    tokenEndpointAuthMethod = 'client_secret_basic',
    updatedAt = datetime('now')
WHERE clientId = 'pg72-copy-preview'
  AND clientSecret IS NOT NULL
  AND length(trim(clientSecret)) > 0
  AND CASE WHEN json_valid(redirectUris) THEN EXISTS (
      SELECT 1
      FROM json_each(redirectUris)
      WHERE value = 'https://sso-integration.cloud-clipboard-c1b.pages.dev/api/auth/callback/pg72-id'
    ) ELSE 0 END;

UPDATE oauthClient
SET scopes = '["openid","profile","email","offline_access"]',
    grantTypes = '["authorization_code","refresh_token"]',
    skipConsent = 0,
    requirePKCE = 1,
    public = 0,
    tokenEndpointAuthMethod = 'client_secret_basic',
    updatedAt = datetime('now')
WHERE clientId = 'pg72-copy'
  AND clientSecret IS NOT NULL
  AND length(trim(clientSecret)) > 0
  AND CASE WHEN json_valid(redirectUris) THEN EXISTS (
      SELECT 1
      FROM json_each(redirectUris)
      WHERE value = 'https://copy.pg72.tw/api/auth/callback/pg72-id'
    ) ELSE 0 END;
