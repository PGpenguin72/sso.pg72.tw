-- 0022 is reserved by the evaluator run-proof ledger integration. This
-- forward migration replaces the archive attempt table because SQLite cannot
-- relax its existing evidence CHECK constraints with ALTER COLUMN.

DROP TRIGGER "audit_archive_attempt_insert_guard";
DROP TRIGGER "audit_archive_attempt_delete_guard";
DROP TRIGGER "audit_archive_attempt_transition_guard";
DROP TRIGGER "audit_archive_batch_claim_attempt";
DROP TRIGGER "audit_archive_attempt_apply_terminal";
DROP TRIGGER "audit_archive_batch_transition_guard";

ALTER TABLE "audit_archive_attempt" RENAME TO "audit_archive_attempt_0021";

CREATE TABLE "audit_archive_attempt" (
  "id" text PRIMARY KEY NOT NULL CHECK (
    length("id") = 43
    AND "id" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("id", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  ),
  "batch_key" text NOT NULL
    REFERENCES "audit_archive_batch" ("batch_key") ON DELETE RESTRICT,
  "dispatch_generation" integer NOT NULL CHECK (
    typeof("dispatch_generation") = 'integer'
    AND "dispatch_generation" BETWEEN 1 AND 1000000
  ),
  "attempt_number" integer NOT NULL CHECK (
    typeof("attempt_number") = 'integer' AND "attempt_number" BETWEEN 1 AND 5
  ),
  "lease_id" text NOT NULL UNIQUE CHECK ("lease_id" = "id"),
  "outcome" text NOT NULL CHECK (
    "outcome" IN (
      'in_flight', 'archived', 'retry', 'dead', 'corrupt', 'lease_expired'
    )
  ),
  "resulting_status" text NOT NULL CHECK (
    "resulting_status" IN (
      'processing', 'archived', 'retry', 'dead', 'corrupt'
    )
  ),
  "next_attempt_at" date CHECK (
    "next_attempt_at" IS NULL OR (
      length("next_attempt_at") = 24
      AND "next_attempt_at" GLOB '????-??-??T??:??:??.???Z'
      AND unixepoch("next_attempt_at") IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "next_attempt_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "next_attempt_at", '+0 seconds'
      ) = "next_attempt_at"
    )
  ),
  "r2_version" text CHECK (
    "r2_version" IS NULL OR (
      length("r2_version") BETWEEN 1 AND 256
      AND instr("r2_version", char(0)) = 0
      AND instr("r2_version", char(10)) = 0
      AND instr("r2_version", char(13)) = 0
    )
  ),
  "r2_etag" text CHECK (
    "r2_etag" IS NULL OR (
      length("r2_etag") BETWEEN 1 AND 256
      AND instr("r2_etag", char(0)) = 0
      AND instr("r2_etag", char(10)) = 0
      AND instr("r2_etag", char(13)) = 0
    )
  ),
  "r2_observed_bytes" integer CHECK (
    "r2_observed_bytes" IS NULL OR (
      typeof("r2_observed_bytes") = 'integer'
      AND "r2_observed_bytes" BETWEEN 0 AND 9007199254740991
    )
  ),
  "r2_stored_sha256" text CHECK (
    "r2_stored_sha256" IS NULL OR (
      length("r2_stored_sha256") = 64
      AND "r2_stored_sha256" NOT GLOB '*[^a-f0-9]*'
    )
  ),
  "r2_readback_sha256" text CHECK (
    "r2_readback_sha256" IS NULL OR (
      length("r2_readback_sha256") = 64
      AND "r2_readback_sha256" NOT GLOB '*[^a-f0-9]*'
    )
  ),
  "r2_readback_at" date CHECK (
    "r2_readback_at" IS NULL OR (
      length("r2_readback_at") = 24
      AND "r2_readback_at" GLOB '????-??-??T??:??:??.???Z'
      AND unixepoch("r2_readback_at") IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "r2_readback_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "r2_readback_at", '+0 seconds'
      ) = "r2_readback_at"
    )
  ),
  "error_code" text CHECK (
    "error_code" IS NULL OR "error_code" IN (
      'queue_unavailable', 'r2_transient', 'r2_object_conflict',
      'r2_readback_mismatch', 'crypto_integrity', 'key_unavailable',
      'lease_expired', 'internal_error'
    )
  ),
  "started_at" date NOT NULL CHECK (
    length("started_at") = 24
    AND "started_at" GLOB '????-??-??T??:??:??.???Z'
    AND unixepoch("started_at") IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "started_at", '+0 seconds')
      IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "started_at", '+0 seconds')
      = "started_at"
  ),
  "completed_at" date CHECK (
    "completed_at" IS NULL OR (
      length("completed_at") = 24
      AND "completed_at" GLOB '????-??-??T??:??:??.???Z'
      AND unixepoch("completed_at") IS NOT NULL
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "completed_at", '+0 seconds')
        IS NOT NULL
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "completed_at", '+0 seconds')
        = "completed_at"
    )
  ),
  UNIQUE ("batch_key", "dispatch_generation", "attempt_number"),
  CHECK ("completed_at" IS NULL OR "completed_at" >= "started_at"),
  CHECK (
    "next_attempt_at" IS NULL OR (
      "completed_at" IS NOT NULL AND "next_attempt_at" >= "completed_at"
    )
  ),
  CHECK (
    ("r2_version" IS NULL AND "r2_etag" IS NULL
      AND "r2_observed_bytes" IS NULL AND "r2_stored_sha256" IS NULL
      AND "r2_readback_sha256" IS NULL AND "r2_readback_at" IS NULL)
    OR ("r2_version" IS NOT NULL AND "r2_etag" IS NOT NULL
      AND "r2_readback_at" IS NOT NULL)
  ),
  CHECK (
    ("outcome" = 'in_flight' AND "resulting_status" = 'processing'
      AND "next_attempt_at" IS NULL AND "r2_version" IS NULL
      AND "error_code" IS NULL AND "completed_at" IS NULL)
    OR ("outcome" = 'archived' AND "resulting_status" = 'archived'
      AND "next_attempt_at" IS NULL AND "r2_version" IS NOT NULL
      AND "r2_readback_sha256" IS NOT NULL
      AND "r2_readback_at" = "completed_at"
      AND "error_code" IS NULL AND "completed_at" IS NOT NULL)
    OR ("outcome" = 'retry' AND "resulting_status" = 'retry'
      AND "attempt_number" BETWEEN 1 AND 4
      AND "next_attempt_at" IS NOT NULL AND "r2_version" IS NULL
      AND "error_code" IS NOT NULL AND "completed_at" IS NOT NULL)
    OR ("outcome" = 'dead' AND "resulting_status" = 'dead'
      AND "attempt_number" = 5
      AND "next_attempt_at" IS NULL AND "r2_version" IS NULL
      AND "error_code" IS NOT NULL AND "completed_at" IS NOT NULL)
    OR ("outcome" = 'corrupt' AND "resulting_status" = 'corrupt'
      AND "next_attempt_at" IS NULL AND "completed_at" IS NOT NULL
      AND (
        ("error_code" = 'crypto_integrity' AND (
          ("r2_version" IS NULL AND "r2_readback_sha256" IS NULL)
          OR ("r2_version" IS NOT NULL
            AND "r2_readback_sha256" IS NOT NULL
            AND "r2_readback_at" = "completed_at")
        ))
        OR ("error_code" = 'r2_object_conflict'
          AND "r2_version" IS NOT NULL
          AND "r2_observed_bytes" IS NOT NULL
          AND "r2_readback_at" = "completed_at")
        OR ("error_code" = 'r2_readback_mismatch'
          AND "r2_version" IS NOT NULL
          AND "r2_readback_sha256" IS NOT NULL
          AND "r2_readback_at" = "completed_at")
      ))
    OR ("outcome" = 'lease_expired'
      AND "resulting_status" = CASE
        WHEN "attempt_number" = 5 THEN 'dead' ELSE 'retry' END
      AND (("attempt_number" < 5 AND "next_attempt_at" IS NOT NULL)
        OR ("attempt_number" = 5 AND "next_attempt_at" IS NULL))
      AND "r2_version" IS NULL AND "error_code" = 'lease_expired'
      AND "completed_at" IS NOT NULL)
  ),
  CHECK (
    "outcome" = 'corrupt' OR "error_code" IS NULL
      OR "error_code" NOT IN (
        'r2_object_conflict', 'r2_readback_mismatch', 'crypto_integrity'
      )
  )
);

INSERT INTO "audit_archive_attempt" (
  "id", "batch_key", "dispatch_generation", "attempt_number", "lease_id",
  "outcome", "resulting_status", "next_attempt_at", "r2_version", "r2_etag",
  "r2_observed_bytes", "r2_stored_sha256", "r2_readback_sha256",
  "r2_readback_at", "error_code", "started_at", "completed_at"
)
SELECT "id", "batch_key", "dispatch_generation", "attempt_number", "lease_id",
       "outcome", "resulting_status", "next_attempt_at", "r2_version", "r2_etag",
       NULL, NULL, "r2_readback_sha256", "r2_readback_at", "error_code",
       "started_at", "completed_at"
  FROM "audit_archive_attempt_0021";

DROP TABLE "audit_archive_attempt_0021";

CREATE INDEX "audit_archive_attempt_time_idx"
  ON "audit_archive_attempt" ("started_at" DESC, "id");

CREATE INDEX "audit_archive_attempt_error_idx"
  ON "audit_archive_attempt" ("error_code", "completed_at" DESC, "id")
  WHERE "error_code" IS NOT NULL;

CREATE INDEX "audit_archive_attempt_outcome_idx"
  ON "audit_archive_attempt" ("outcome", "completed_at" DESC, "id");

CREATE TRIGGER "audit_archive_attempt_insert_guard"
BEFORE INSERT ON "audit_archive_attempt"
WHEN EXISTS (
  SELECT 1 FROM "audit_archive_attempt"
   WHERE "id" = NEW."id" OR "lease_id" = NEW."lease_id"
      OR ("batch_key" = NEW."batch_key"
        AND "dispatch_generation" = NEW."dispatch_generation"
        AND "attempt_number" = NEW."attempt_number")
)
OR NEW."outcome" <> 'in_flight'
OR NOT EXISTS (
  SELECT 1 FROM "audit_archive_batch" AS batch
   WHERE batch."batch_key" = NEW."batch_key"
     AND batch."status" = 'processing'
     AND batch."dispatch_generation" = NEW."dispatch_generation"
     AND batch."attempts" = NEW."attempt_number"
     AND batch."lease_id" = NEW."lease_id"
     AND NEW."started_at" = batch."updated_at"
     AND NEW."started_at" < batch."lease_expires_at"
)
BEGIN
  SELECT RAISE(ABORT, 'audit archive attempt does not match active claim');
END;

CREATE TRIGGER "audit_archive_attempt_delete_guard"
BEFORE DELETE ON "audit_archive_attempt"
BEGIN
  SELECT RAISE(ABORT, 'audit archive attempt is immutable');
END;

CREATE TRIGGER "audit_archive_attempt_transition_guard"
BEFORE UPDATE ON "audit_archive_attempt"
WHEN OLD."outcome" <> 'in_flight'
  OR NEW."id" <> OLD."id"
  OR NEW."batch_key" <> OLD."batch_key"
  OR NEW."dispatch_generation" <> OLD."dispatch_generation"
  OR NEW."attempt_number" <> OLD."attempt_number"
  OR NEW."lease_id" <> OLD."lease_id"
  OR NEW."started_at" <> OLD."started_at"
  OR NEW."outcome" NOT IN (
    'archived', 'retry', 'dead', 'corrupt', 'lease_expired'
  )
  OR NOT EXISTS (
    SELECT 1 FROM "audit_archive_batch" AS batch
     WHERE batch."batch_key" = OLD."batch_key"
       AND batch."status" = 'processing'
       AND batch."dispatch_generation" = OLD."dispatch_generation"
       AND batch."attempts" = OLD."attempt_number"
       AND batch."lease_id" = OLD."lease_id"
       AND (
         (NEW."outcome" = 'lease_expired'
           AND NEW."completed_at" >= batch."lease_expires_at")
         OR (NEW."outcome" <> 'lease_expired'
           AND NEW."completed_at" < batch."lease_expires_at")
       )
       AND (
         NEW."outcome" <> 'archived'
         OR NEW."r2_readback_sha256" = batch."object_sha256"
       )
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid audit archive attempt transition');
END;

CREATE TRIGGER "audit_archive_batch_claim_attempt"
AFTER UPDATE ON "audit_archive_batch"
WHEN OLD."status" IN ('pending', 'retry') AND NEW."status" = 'processing'
BEGIN
  INSERT INTO "audit_archive_attempt" (
    "id", "batch_key", "dispatch_generation", "attempt_number", "lease_id",
    "outcome", "resulting_status", "next_attempt_at",
    "r2_version", "r2_etag", "r2_observed_bytes", "r2_stored_sha256",
    "r2_readback_sha256", "r2_readback_at", "error_code", "started_at",
    "completed_at"
  ) VALUES (
    NEW."lease_id", NEW."batch_key", NEW."dispatch_generation", NEW."attempts",
    NEW."lease_id", 'in_flight', 'processing', NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NEW."updated_at", NULL
  );
END;

CREATE TRIGGER "audit_archive_attempt_apply_terminal"
AFTER UPDATE ON "audit_archive_attempt"
WHEN OLD."outcome" = 'in_flight' AND NEW."outcome" <> 'in_flight'
BEGIN
  UPDATE "audit_archive_batch"
     SET "status" = CASE NEW."outcome"
           WHEN 'archived' THEN 'archived'
           WHEN 'retry' THEN 'retry'
           WHEN 'dead' THEN 'dead'
           WHEN 'corrupt' THEN 'corrupt'
           WHEN 'lease_expired' THEN
             CASE WHEN NEW."attempt_number" = 5 THEN 'dead' ELSE 'retry' END
         END,
         "next_attempt_at" = NEW."next_attempt_at",
         "lease_id" = NULL,
         "lease_expires_at" = NULL,
         "r2_version" = CASE WHEN NEW."outcome" = 'archived'
           THEN NEW."r2_version" ELSE NULL END,
         "r2_etag" = CASE WHEN NEW."outcome" = 'archived'
           THEN NEW."r2_etag" ELSE NULL END,
         "r2_readback_sha256" = CASE WHEN NEW."outcome" = 'archived'
           THEN NEW."r2_readback_sha256" ELSE NULL END,
         "r2_readback_at" = CASE WHEN NEW."outcome" = 'archived'
           THEN NEW."r2_readback_at" ELSE NULL END,
         "archived_at" = CASE WHEN NEW."outcome" = 'archived'
           THEN NEW."completed_at" ELSE NULL END,
         "envelope_gc_at" = CASE WHEN NEW."outcome" = 'archived'
           THEN NEW."completed_at" ELSE NULL END,
         "encrypted_envelope" = CASE WHEN NEW."outcome" = 'archived'
           THEN NULL ELSE "encrypted_envelope" END,
         "last_error_code" = NEW."error_code",
         "updated_at" = NEW."completed_at"
   WHERE "batch_key" = OLD."batch_key"
     AND "status" = 'processing'
     AND "dispatch_generation" = OLD."dispatch_generation"
     AND "attempts" = OLD."attempt_number"
     AND "lease_id" = OLD."lease_id";
END;

CREATE TRIGGER "audit_archive_batch_transition_guard"
BEFORE UPDATE ON "audit_archive_batch"
WHEN NEW."updated_at" <= OLD."updated_at"
OR NOT (
  (OLD."status" IN ('pending', 'retry')
    AND NEW."status" = 'processing'
    AND NEW."dispatch_generation" = OLD."dispatch_generation"
    AND NEW."attempts" = OLD."attempts" + 1
    AND NEW."next_attempt_at" IS NULL
    AND NEW."lease_id" IS NOT NULL
    AND NEW."lease_id" IS NOT OLD."lease_id"
    AND NEW."lease_expires_at" IS NOT NULL
    AND NEW."updated_at" >= OLD."next_attempt_at"
    AND NEW."lease_expires_at" > NEW."updated_at"
    AND NEW."lease_expires_at" <= strftime(
      '%Y-%m-%dT%H:%M:%fZ', NEW."updated_at", '+300 seconds'
    )
    AND NEW."r2_version" IS OLD."r2_version"
    AND NEW."r2_etag" IS OLD."r2_etag"
    AND NEW."r2_readback_sha256" IS OLD."r2_readback_sha256"
    AND NEW."r2_readback_at" IS OLD."r2_readback_at"
    AND NEW."archived_at" IS OLD."archived_at"
    AND NEW."envelope_gc_at" IS OLD."envelope_gc_at"
    AND NEW."last_error_code" IS NULL
    AND NEW."manual_replay_audit_id" IS OLD."manual_replay_audit_id")
  OR (OLD."status" = 'processing' AND NEW."status" = 'processing'
    AND NEW."dispatch_generation" = OLD."dispatch_generation"
    AND NEW."attempts" = OLD."attempts"
    AND NEW."next_attempt_at" IS NULL
    AND NEW."lease_id" IS NOT NULL
    AND NEW."lease_id" = OLD."lease_id"
    AND NEW."updated_at" > OLD."updated_at"
    AND NEW."updated_at" < OLD."lease_expires_at"
    AND NEW."lease_expires_at" > OLD."lease_expires_at"
    AND NEW."lease_expires_at" > NEW."updated_at"
    AND NEW."lease_expires_at" <= strftime(
      '%Y-%m-%dT%H:%M:%fZ', NEW."updated_at", '+300 seconds'
    )
    AND NEW."r2_version" IS OLD."r2_version"
    AND NEW."r2_etag" IS OLD."r2_etag"
    AND NEW."r2_readback_sha256" IS OLD."r2_readback_sha256"
    AND NEW."r2_readback_at" IS OLD."r2_readback_at"
    AND NEW."archived_at" IS OLD."archived_at"
    AND NEW."envelope_gc_at" IS OLD."envelope_gc_at"
    AND NEW."last_error_code" IS OLD."last_error_code"
    AND NEW."manual_replay_audit_id" IS OLD."manual_replay_audit_id"
    AND EXISTS (
      SELECT 1 FROM "audit_archive_attempt" AS attempt
       WHERE attempt."batch_key" = OLD."batch_key"
         AND attempt."dispatch_generation" = OLD."dispatch_generation"
         AND attempt."attempt_number" = OLD."attempts"
         AND attempt."lease_id" = OLD."lease_id"
         AND attempt."outcome" = 'in_flight'
    ))
  OR (OLD."status" = 'processing'
    AND NEW."status" IN ('archived', 'retry', 'dead', 'corrupt')
    AND NEW."dispatch_generation" = OLD."dispatch_generation"
    AND NEW."attempts" = OLD."attempts"
    AND NEW."lease_id" IS NULL AND NEW."lease_expires_at" IS NULL
    AND NEW."manual_replay_audit_id" IS OLD."manual_replay_audit_id"
    AND EXISTS (
      SELECT 1 FROM "audit_archive_attempt" AS attempt
       WHERE attempt."batch_key" = OLD."batch_key"
         AND attempt."dispatch_generation" = OLD."dispatch_generation"
         AND attempt."attempt_number" = OLD."attempts"
         AND attempt."lease_id" = OLD."lease_id"
         AND attempt."outcome" <> 'in_flight'
         AND attempt."resulting_status" = NEW."status"
         AND attempt."next_attempt_at" IS NEW."next_attempt_at"
         AND attempt."error_code" IS NEW."last_error_code"
         AND attempt."completed_at" = NEW."updated_at"
         AND (
           (NEW."status" = 'archived'
             AND attempt."outcome" = 'archived'
             AND attempt."r2_version" = NEW."r2_version"
             AND attempt."r2_etag" = NEW."r2_etag"
             AND attempt."r2_readback_sha256" = NEW."r2_readback_sha256"
             AND attempt."r2_readback_at" = NEW."r2_readback_at"
             AND NEW."archived_at" = attempt."completed_at"
             AND NEW."envelope_gc_at" = attempt."completed_at")
           OR (NEW."status" <> 'archived'
             AND NEW."r2_version" IS NULL
             AND NEW."archived_at" IS NULL
             AND NEW."envelope_gc_at" IS NULL)
         )
    ))
  OR (OLD."status" = 'dead'
    AND NEW."status" = 'pending'
    AND NEW."dispatch_generation" = OLD."dispatch_generation" + 1
    AND NEW."attempts" = 0
    AND NEW."next_attempt_at" IS NOT NULL
    AND NEW."next_attempt_at" >= NEW."updated_at"
    AND NEW."lease_id" IS NULL AND NEW."lease_expires_at" IS NULL
    AND NEW."r2_version" IS NULL AND NEW."archived_at" IS NULL
    AND NEW."envelope_gc_at" IS NULL AND NEW."last_error_code" IS NULL
    AND NEW."manual_replay_audit_id" IS NOT NULL
    AND NEW."manual_replay_audit_id" IS NOT OLD."manual_replay_audit_id"
    AND EXISTS (
      SELECT 1 FROM "audit_event" AS event
       WHERE event."id" = NEW."manual_replay_audit_id"
         AND event."event_type" = 'audit.archive.manual_replay'
         AND event."outcome" = 'success'
         AND event."subject_id" = OLD."batch_key"
         AND event."metadata_json" = json_object(
           'dispatchGeneration', NEW."dispatch_generation"
         )
         AND event."occurred_at" = NEW."updated_at"
    ))
)
BEGIN
  SELECT RAISE(ABORT, 'invalid audit archive batch transition');
END;
