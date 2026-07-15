UPDATE oauthClient
SET skipConsent = 0,
    updatedAt = datetime('now')
WHERE COALESCE(skipConsent, 0) <> 0;

UPDATE oauthClient
SET name = 'PG72 Copy Preview',
    uri = 'https://sso-integration.cloud-clipboard-c1b.pages.dev',
    updatedAt = datetime('now')
WHERE clientId = 'pg72-copy-preview';

CREATE TRIGGER oauth_client_consent_insert_guard
BEFORE INSERT ON oauthClient
WHEN COALESCE(NEW.skipConsent, 0) <> 0
BEGIN
  SELECT RAISE(ABORT, 'oauth consent cannot be skipped');
END;

CREATE TRIGGER oauth_client_consent_update_guard
BEFORE UPDATE OF skipConsent ON oauthClient
WHEN COALESCE(NEW.skipConsent, 0) <> 0
BEGIN
  SELECT RAISE(ABORT, 'oauth consent cannot be skipped');
END;
