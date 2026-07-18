-- Forward-only guard for current R2 readback evidence. Existing immutable
-- 0021 conflict rows retain their explicit legacy discriminator from 0023.
CREATE TRIGGER "audit_archive_attempt_current_r2_evidence_guard"
BEFORE UPDATE ON "audit_archive_attempt"
WHEN OLD."outcome" = 'in_flight'
  AND NEW."outcome" = 'corrupt'
  AND NEW."error_code" IN ('crypto_integrity', 'r2_readback_mismatch')
  AND NEW."r2_version" IS NOT NULL
  AND NEW."r2_observed_bytes" IS NULL
BEGIN
  SELECT RAISE(ABORT, 'current R2 evidence requires observed bytes');
END;
