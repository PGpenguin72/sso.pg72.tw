-- Consent-screen trust metadata backfill.
--
-- The consent screen now shows the developer identity for every client. New
-- clients must provide `developerName` through the admin API (stored in the
-- oauthClient.metadata JSON column as `developer_name`, preserving unrelated
-- keys such as the diary client's `backchannel_logout_uri`). This migration
-- backfills the known first-party clients created before the field existed;
-- any other legacy row without a developer name renders as the neutral
-- fallback "PG72 官方" until an administrator fills it in via the edit form.
UPDATE oauthClient
SET metadata = json_set(
      CASE WHEN json_valid(COALESCE(metadata, '')) THEN metadata ELSE '{}' END,
      '$.developer_name',
      'PG72 官方'
    ),
    updatedAt = datetime('now')
WHERE clientId IN (
    'pg72-test-rp',
    'pg72-diary',
    'pg72-diary-dev',
    'pg72-copy',
    'pg72-copy-preview'
  )
  AND (
    CASE WHEN json_valid(COALESCE(metadata, ''))
         THEN json_extract(metadata, '$.developer_name')
    END
  ) IS NULL;
