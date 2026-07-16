-- A provider identity is immutable and may belong to exactly one PGID user.
-- Deployment must stop if the read-only duplicate preflight finds any rows.
CREATE UNIQUE INDEX account_provider_identity_unique
ON account(providerId, accountId);
