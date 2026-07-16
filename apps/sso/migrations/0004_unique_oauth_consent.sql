DELETE FROM oauthConsent
WHERE rowid IN (
  SELECT duplicate_rowid
  FROM (
    SELECT rowid AS duplicate_rowid,
           ROW_NUMBER() OVER (
             PARTITION BY clientId, userId, referenceId
             ORDER BY updatedAt DESC, rowid DESC
           ) AS consent_rank
    FROM oauthConsent
  )
  WHERE consent_rank > 1
);

CREATE UNIQUE INDEX oauth_consent_user_client_unique
  ON oauthConsent (clientId, userId)
  WHERE userId IS NOT NULL AND referenceId IS NULL;

CREATE UNIQUE INDEX oauth_consent_user_client_reference_unique
  ON oauthConsent (clientId, userId, referenceId)
  WHERE userId IS NOT NULL AND referenceId IS NOT NULL;
