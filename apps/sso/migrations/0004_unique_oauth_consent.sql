DELETE FROM oauthConsent
WHERE rowid NOT IN (
  SELECT MAX(rowid)
  FROM oauthConsent
  GROUP BY clientId, userId, COALESCE(referenceId, '')
);

CREATE UNIQUE INDEX oauth_consent_user_client_unique
  ON oauthConsent (clientId, userId)
  WHERE userId IS NOT NULL AND referenceId IS NULL;

CREATE UNIQUE INDEX oauth_consent_user_client_reference_unique
  ON oauthConsent (clientId, userId, referenceId)
  WHERE userId IS NOT NULL AND referenceId IS NOT NULL;
