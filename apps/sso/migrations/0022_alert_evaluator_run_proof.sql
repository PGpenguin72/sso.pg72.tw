-- Immutable evaluator run/source/decision proof ledger.
--
-- This migration is deliberately unwired. It adds the transaction fences used
-- by a future evaluator, but does not add Cron code, Queue bindings, Email
-- delivery, configuration, secrets, or a production migration.

CREATE TABLE "alert_evaluator_run" (
  "id" text PRIMARY KEY NOT NULL CHECK (
    length("id") = 36
    AND "id" = lower("id")
    AND substr("id", 9, 1) = '-'
    AND substr("id", 14, 1) = '-'
    AND substr("id", 15, 1) = '4'
    AND substr("id", 19, 1) = '-'
    AND substr("id", 20, 1) IN ('8', '9', 'a', 'b')
    AND substr("id", 24, 1) = '-'
    AND replace("id", '-', '') NOT GLOB '*[^a-f0-9]*'
  ),
  "component" text NOT NULL CHECK ("component" = 'evaluator'),
  "trigger_cron" text NOT NULL CHECK ("trigger_cron" = '* * * * *'),
  "trigger_scheduled_at" date NOT NULL CHECK (
    typeof("trigger_scheduled_at") = 'text'
    AND length("trigger_scheduled_at") = 24
    AND strftime(
      '%Y-%m-%dT%H:%M:%fZ', "trigger_scheduled_at", '+0 seconds'
    ) = "trigger_scheduled_at"
  ),
  "runtime_generation" integer NOT NULL CHECK (
    typeof("runtime_generation") = 'integer'
    AND "runtime_generation" BETWEEN 1 AND 9007199254740991
  ),
  "acquired_revision" integer NOT NULL CHECK (
    typeof("acquired_revision") = 'integer'
    AND "acquired_revision" BETWEEN 1 AND 9007199254740990
  ),
  "lease_revision" integer NOT NULL CHECK (
    typeof("lease_revision") = 'integer'
    AND "lease_revision" BETWEEN 1 AND 9007199254740990
    AND "lease_revision" >= "acquired_revision"
  ),
  "lease_id" text NOT NULL CHECK (
    length("lease_id") = 36
    AND "lease_id" = lower("lease_id")
    AND substr("lease_id", 9, 1) = '-'
    AND substr("lease_id", 14, 1) = '-'
    AND substr("lease_id", 15, 1) = '4'
    AND substr("lease_id", 19, 1) = '-'
    AND substr("lease_id", 20, 1) IN ('8', '9', 'a', 'b')
    AND substr("lease_id", 24, 1) = '-'
    AND replace("lease_id", '-', '') NOT GLOB '*[^a-f0-9]*'
  ),
  "started_at" date NOT NULL CHECK (
    typeof("started_at") = 'text'
    AND length("started_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "started_at", '+0 seconds')
      = "started_at"
  ),
  "lease_updated_at" date NOT NULL CHECK (
    typeof("lease_updated_at") = 'text'
    AND length("lease_updated_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "lease_updated_at", '+0 seconds')
      = "lease_updated_at"
  ),
  "lease_expires_at" date NOT NULL CHECK (
    typeof("lease_expires_at") = 'text'
    AND length("lease_expires_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "lease_expires_at", '+0 seconds')
      = "lease_expires_at"
  ),
  "as_of" date CHECK (
    "as_of" IS NULL OR (
      typeof("as_of") = 'text'
      AND length("as_of") = 24
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "as_of", '+0 seconds') = "as_of"
    )
  ),
  "source_count" integer CHECK (
    "source_count" IS NULL OR (
      typeof("source_count") = 'integer' AND "source_count" = 9
    )
  ),
  "partial_source_count" integer CHECK (
    "partial_source_count" IS NULL OR (
      typeof("partial_source_count") = 'integer'
      AND "partial_source_count" BETWEEN 0 AND 9
    )
  ),
  "source_manifest_sha256" text CHECK (
    "source_manifest_sha256" IS NULL OR (
      length("source_manifest_sha256") = 43
      AND "source_manifest_sha256" NOT GLOB '*[^A-Za-z0-9_-]*'
      AND substr("source_manifest_sha256", -1) IN (
        'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
        'g', 'k', 'o', 's', 'w', '0', '4', '8'
      )
    )
  ),
  "decision_count" integer CHECK (
    "decision_count" IS NULL OR (
      typeof("decision_count") = 'integer'
      AND "decision_count" BETWEEN 0 AND 10000
    )
  ),
  "decision_manifest_sha256" text CHECK (
    "decision_manifest_sha256" IS NULL OR (
      length("decision_manifest_sha256") = 43
      AND "decision_manifest_sha256" NOT GLOB '*[^A-Za-z0-9_-]*'
      AND substr("decision_manifest_sha256", -1) IN (
        'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
        'g', 'k', 'o', 's', 'w', '0', '4', '8'
      )
    )
  ),
  "status" text NOT NULL CHECK (
    "status" IN ('running', 'sealed', 'succeeded', 'failed', 'abandoned')
  ),
  "completed_at" date CHECK (
    "completed_at" IS NULL OR (
      typeof("completed_at") = 'text'
      AND length("completed_at") = 24
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "completed_at", '+0 seconds')
        = "completed_at"
    )
  ),
  "watermark_at" date CHECK (
    "watermark_at" IS NULL OR (
      typeof("watermark_at") = 'text'
      AND length("watermark_at") = 24
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "watermark_at", '+0 seconds')
        = "watermark_at"
    )
  ),
  "terminal_runtime_revision" integer CHECK (
    "terminal_runtime_revision" IS NULL OR (
      typeof("terminal_runtime_revision") = 'integer'
      AND "terminal_runtime_revision" BETWEEN 2 AND 9007199254740991
    )
  ),
  "failure_status" text CHECK (
    "failure_status" IS NULL
    OR "failure_status" IN ('degraded', 'failing', 'unavailable')
  ),
  "failure_error_code" text CHECK (
    "failure_error_code" IS NULL
    OR "failure_error_code" IN (
      'evaluator_failed', 'metrics_unavailable', 'source_incomplete', 'unknown'
    )
  ),
  "created_at" date NOT NULL CHECK (
    typeof("created_at") = 'text'
    AND length("created_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds')
      = "created_at"
  ),
  "updated_at" date NOT NULL CHECK (
    typeof("updated_at") = 'text'
    AND length("updated_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "updated_at", '+0 seconds')
      = "updated_at"
  ),
  UNIQUE ("trigger_cron", "trigger_scheduled_at"),
  UNIQUE ("component", "runtime_generation"),
  FOREIGN KEY ("component") REFERENCES "alert_runtime_status" ("component")
    ON DELETE RESTRICT,
  CHECK ("trigger_scheduled_at" <= "started_at"),
  CHECK ("created_at" = "started_at"),
  CHECK ("lease_updated_at" >= "started_at"),
  CHECK ("lease_expires_at" > "lease_updated_at"),
  CHECK (
    "lease_expires_at" <= strftime(
      '%Y-%m-%dT%H:%M:%fZ', "lease_updated_at", '+300 seconds'
    )
  ),
  CHECK ("updated_at" >= "created_at"),
  CHECK (
    ("source_count" IS NULL
      AND "partial_source_count" IS NULL
      AND "source_manifest_sha256" IS NULL
      AND "decision_count" IS NULL
      AND "decision_manifest_sha256" IS NULL)
    OR ("as_of" IS NOT NULL
      AND "source_count" = 9
      AND "partial_source_count" IS NOT NULL
      AND "source_manifest_sha256" IS NOT NULL
      AND "decision_count" IS NOT NULL
      AND "decision_manifest_sha256" IS NOT NULL)
  ),
  CHECK (
    ("status" = 'running'
      AND "source_count" IS NULL
      AND "completed_at" IS NULL
      AND "watermark_at" IS NULL
      AND "terminal_runtime_revision" IS NULL
      AND "failure_status" IS NULL
      AND "failure_error_code" IS NULL)
    OR ("status" = 'sealed'
      AND "source_count" = 9
      AND "completed_at" IS NULL
      AND "watermark_at" IS NULL
      AND "terminal_runtime_revision" IS NULL
      AND "failure_status" IS NULL
      AND "failure_error_code" IS NULL)
    OR ("status" = 'succeeded'
      AND "source_count" = 9
      AND "partial_source_count" = 0
      AND "completed_at" IS NOT NULL
      AND "watermark_at" = "as_of"
      AND "terminal_runtime_revision" = "lease_revision" + 1
      AND "failure_status" IS NULL
      AND "failure_error_code" IS NULL)
    OR ("status" = 'failed'
      AND "completed_at" IS NOT NULL
      AND "watermark_at" IS NULL
      AND "terminal_runtime_revision" = "lease_revision" + 1
      AND "failure_status" IS NOT NULL
      AND "failure_error_code" IS NOT NULL
      AND (
        ("failure_status" = 'degraded'
          AND "failure_error_code" = 'source_incomplete')
        OR ("failure_status" = 'unavailable'
          AND "failure_error_code" = 'metrics_unavailable')
        OR ("failure_status" = 'failing'
          AND "failure_error_code" IN ('evaluator_failed', 'unknown'))
      ))
    OR ("status" = 'abandoned'
      AND "completed_at" IS NOT NULL
      AND "completed_at" >= "lease_expires_at"
      AND "watermark_at" IS NULL
      AND "terminal_runtime_revision" IS NULL
      AND "failure_status" IS NULL
      AND "failure_error_code" IS NULL)
  ),
  CHECK (
    "completed_at" IS NULL OR (
      "completed_at" >= "started_at" AND "updated_at" = "completed_at"
    )
  )
);

CREATE TABLE "alert_evaluator_run_source" (
  "run_id" text NOT NULL,
  "source_id" text NOT NULL CHECK (
    "source_id" IN (
      'queue.security_events_dlq',
      'queue.logout_deliveries_dlq',
      'queue.alert_deliveries_dlq',
      'queue.audit_archive_dlq',
      'd1.audit',
      'd1.oauth_client_report',
      'd1.security_fanout_gap',
      'd1.logout_delivery',
      'd1.alert_runtime'
    )
  ),
  "as_of" date NOT NULL CHECK (
    typeof("as_of") = 'text'
    AND length("as_of") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "as_of", '+0 seconds') = "as_of"
  ),
  "status" text NOT NULL CHECK (
    "status" IN ('complete', 'partial', 'unavailable', 'invalid')
  ),
  "observation_count" integer NOT NULL CHECK (
    typeof("observation_count") = 'integer'
    AND "observation_count" BETWEEN 0 AND 10000
  ),
  "incomplete_count" integer NOT NULL CHECK (
    typeof("incomplete_count") = 'integer'
    AND "incomplete_count" BETWEEN 0 AND 10000
  ),
  "proof_sha256" text NOT NULL CHECK (
    length("proof_sha256") = 43
    AND "proof_sha256" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("proof_sha256", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  ),
  "runtime_generation" integer NOT NULL CHECK (
    typeof("runtime_generation") = 'integer'
    AND "runtime_generation" BETWEEN 1 AND 9007199254740991
  ),
  "runtime_revision" integer NOT NULL CHECK (
    typeof("runtime_revision") = 'integer'
    AND "runtime_revision" BETWEEN 1 AND 9007199254740990
  ),
  "recorded_at" date NOT NULL CHECK (
    typeof("recorded_at") = 'text'
    AND length("recorded_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "recorded_at", '+0 seconds')
      = "recorded_at"
  ),
  PRIMARY KEY ("run_id", "source_id"),
  FOREIGN KEY ("run_id") REFERENCES "alert_evaluator_run" ("id")
    ON DELETE RESTRICT,
  CHECK (
    ("status" = 'complete' AND "incomplete_count" = 0)
    OR ("status" = 'partial' AND "incomplete_count" BETWEEN 1 AND 10000)
    OR ("status" IN ('unavailable', 'invalid')
      AND "observation_count" = 0 AND "incomplete_count" = 0)
  )
);

CREATE TABLE "alert_evaluator_run_decision" (
  "run_id" text NOT NULL,
  "source_id" text NOT NULL CHECK (
    "source_id" IN (
      'queue.security_events_dlq',
      'queue.logout_deliveries_dlq',
      'queue.alert_deliveries_dlq',
      'queue.audit_archive_dlq',
      'd1.audit',
      'd1.oauth_client_report',
      'd1.security_fanout_gap',
      'd1.logout_delivery',
      'd1.alert_runtime'
    )
  ),
  "ordinal" integer NOT NULL CHECK (
    typeof("ordinal") = 'integer' AND "ordinal" BETWEEN 0 AND 9999
  ),
  "identity_sha256" text NOT NULL CHECK (
    length("identity_sha256") = 43
    AND "identity_sha256" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("identity_sha256", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  ),
  "evaluation_sha256" text NOT NULL CHECK (
    length("evaluation_sha256") = 43
    AND "evaluation_sha256" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("evaluation_sha256", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  ),
  "decision_sha256" text NOT NULL CHECK (
    length("decision_sha256") = 43
    AND "decision_sha256" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("decision_sha256", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  ),
  "disposition" text NOT NULL CHECK (
    "disposition" IN (
      'applied', 'no_state_change', 'suppressed_partial'
    )
  ),
  "as_of" date NOT NULL CHECK (
    typeof("as_of") = 'text'
    AND length("as_of") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "as_of", '+0 seconds') = "as_of"
  ),
  "state_id" text REFERENCES "alert_state" ("id") ON DELETE RESTRICT,
  "state_generation" integer CHECK (
    "state_generation" IS NULL OR (
      typeof("state_generation") = 'integer'
      AND "state_generation" BETWEEN 0 AND 1000000
    )
  ),
  "state_revision" integer CHECK (
    "state_revision" IS NULL OR (
      typeof("state_revision") = 'integer'
      AND "state_revision" BETWEEN 0 AND 1000000000
    )
  ),
  "runtime_generation" integer NOT NULL CHECK (
    typeof("runtime_generation") = 'integer'
    AND "runtime_generation" BETWEEN 1 AND 9007199254740991
  ),
  "runtime_revision" integer NOT NULL CHECK (
    typeof("runtime_revision") = 'integer'
    AND "runtime_revision" BETWEEN 1 AND 9007199254740990
  ),
  "recorded_at" date NOT NULL CHECK (
    typeof("recorded_at") = 'text'
    AND length("recorded_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "recorded_at", '+0 seconds')
      = "recorded_at"
  ),
  PRIMARY KEY ("run_id", "ordinal"),
  UNIQUE ("run_id", "identity_sha256"),
  FOREIGN KEY ("run_id") REFERENCES "alert_evaluator_run" ("id")
    ON DELETE RESTRICT,
  FOREIGN KEY ("run_id", "source_id")
    REFERENCES "alert_evaluator_run_source" ("run_id", "source_id")
    ON DELETE RESTRICT,
  CHECK (
    ("disposition" = 'applied'
      AND "state_id" IS NOT NULL
      AND "state_generation" IS NOT NULL
      AND "state_revision" IS NOT NULL)
    OR ("disposition" IN ('no_state_change', 'suppressed_partial')
      AND "state_id" IS NULL
      AND "state_generation" IS NULL
      AND "state_revision" IS NULL)
  )
);

-- A run insert is the only evaluator lease-acquisition primitive after 0022.
-- The trigger body is one SQLite statement transaction: any later RAISE rolls
-- back predecessor abandonment, runtime acquisition, and the inserted run.
CREATE TRIGGER "alert_evaluator_run_acquire_runtime"
AFTER INSERT ON "alert_evaluator_run"
BEGIN
  UPDATE "alert_evaluator_run"
     SET "status" = 'abandoned',
         "completed_at" = NEW."started_at",
         "updated_at" = NEW."started_at"
   WHERE "component" = NEW."component"
     AND "runtime_generation" = NEW."runtime_generation" - 1
     AND "status" IN ('running', 'sealed')
     AND "lease_expires_at" <= NEW."started_at";

  UPDATE "alert_runtime_status"
     SET "generation" = NEW."runtime_generation",
         "revision" = NEW."acquired_revision",
         "lease_id" = NEW."lease_id",
         "lease_expires_at" = NEW."lease_expires_at",
         "last_started_at" = NEW."started_at",
         "updated_at" = NEW."lease_updated_at"
   WHERE "component" = NEW."component"
     AND "generation" = NEW."runtime_generation" - 1
     AND "revision" = NEW."acquired_revision" - 1
     AND "generation" < 9007199254740991
     AND "revision" < 9007199254740990
     AND "updated_at" < NEW."started_at"
     AND ("lease_id" IS NULL OR "lease_expires_at" <= NEW."started_at");

  SELECT CASE WHEN changes() <> 1
    THEN RAISE(ABORT, 'evaluator run failed to acquire exact runtime lease')
  END;
END;

CREATE TRIGGER "alert_evaluator_run_insert_shape_guard"
BEFORE INSERT ON "alert_evaluator_run"
WHEN NEW."status" <> 'running'
  OR NEW."runtime_generation" < 1
  OR NEW."acquired_revision" <> NEW."lease_revision"
  OR NEW."lease_updated_at" <> NEW."started_at"
  OR NEW."as_of" IS NOT NULL
  OR NEW."source_count" IS NOT NULL
  OR NEW."completed_at" IS NOT NULL
  OR NEW."created_at" <> NEW."started_at"
  OR NEW."updated_at" <> NEW."started_at"
BEGIN
  SELECT RAISE(ABORT, 'invalid initial evaluator run');
END;

CREATE TRIGGER "alert_evaluator_run_conflict_guard"
BEFORE INSERT ON "alert_evaluator_run"
WHEN EXISTS (
  SELECT 1 FROM "alert_evaluator_run"
   WHERE "id" = NEW."id"
      OR ("trigger_cron" = NEW."trigger_cron"
        AND "trigger_scheduled_at" = NEW."trigger_scheduled_at")
      OR ("component" = NEW."component"
        AND "runtime_generation" = NEW."runtime_generation")
)
BEGIN
  SELECT RAISE(ABORT, 'evaluator run proof is immutable');
END;

-- Direct legacy evaluator lease acquisition and renewal cannot bypass a run.
-- Run INSERT/UPDATE triggers have already made the matching row visible before
-- these runtime updates execute.
CREATE TRIGGER "alert_runtime_evaluator_lease_run_guard"
BEFORE UPDATE ON "alert_runtime_status"
WHEN OLD."component" = 'evaluator'
  AND NEW."lease_id" IS NOT NULL
  AND (
    OLD."lease_id" IS NULL
    OR NEW."lease_id" IS NOT OLD."lease_id"
    OR NEW."revision" <> OLD."revision"
  )
  AND NOT EXISTS (
    SELECT 1
      FROM "alert_evaluator_run" AS run
     WHERE run."component" = 'evaluator'
       AND run."runtime_generation" = NEW."generation"
       AND run."lease_revision" = NEW."revision"
       AND run."lease_id" = NEW."lease_id"
       AND run."started_at" = NEW."last_started_at"
       AND run."lease_updated_at" = NEW."updated_at"
       AND run."lease_expires_at" = NEW."lease_expires_at"
       AND run."status" IN ('running', 'sealed')
  )
BEGIN
  SELECT RAISE(ABORT, 'evaluator runtime lease requires exact run proof');
END;

CREATE TRIGGER "alert_runtime_evaluator_idle_update_guard"
BEFORE UPDATE ON "alert_runtime_status"
WHEN OLD."component" = 'evaluator'
  AND OLD."lease_id" IS NULL
  AND NEW."lease_id" IS NULL
BEGIN
  SELECT RAISE(ABORT, 'idle evaluator runtime is immutable');
END;

CREATE TRIGGER "alert_evaluator_run_transition_guard"
BEFORE UPDATE ON "alert_evaluator_run"
WHEN NEW."id" <> OLD."id"
  OR NEW."component" <> OLD."component"
  OR NEW."trigger_cron" <> OLD."trigger_cron"
  OR NEW."trigger_scheduled_at" <> OLD."trigger_scheduled_at"
  OR NEW."runtime_generation" <> OLD."runtime_generation"
  OR NEW."acquired_revision" <> OLD."acquired_revision"
  OR NEW."lease_id" <> OLD."lease_id"
  OR NEW."started_at" <> OLD."started_at"
  OR NEW."created_at" <> OLD."created_at"
  OR NEW."updated_at" <= OLD."updated_at"
  OR OLD."status" IN ('succeeded', 'failed', 'abandoned')
  OR NOT (
    -- Exact same-owner renewal, including after sealing.
    (OLD."status" IN ('running', 'sealed')
      AND NEW."status" = OLD."status"
      AND NEW."lease_revision" = OLD."lease_revision" + 1
      AND NEW."lease_updated_at" > OLD."lease_updated_at"
      AND NEW."lease_expires_at" >= OLD."lease_expires_at"
      AND NEW."updated_at" = NEW."lease_updated_at"
      AND NEW."as_of" IS OLD."as_of"
      AND NEW."source_count" IS OLD."source_count"
      AND NEW."partial_source_count" IS OLD."partial_source_count"
      AND NEW."source_manifest_sha256" IS OLD."source_manifest_sha256"
      AND NEW."decision_count" IS OLD."decision_count"
      AND NEW."decision_manifest_sha256" IS OLD."decision_manifest_sha256"
      AND NEW."completed_at" IS NULL
      AND NEW."watermark_at" IS NULL
      AND NEW."terminal_runtime_revision" IS NULL
      AND NEW."failure_status" IS NULL
      AND NEW."failure_error_code" IS NULL)
    -- Bind the completion asOf exactly once.
    OR (OLD."status" = 'running' AND NEW."status" = 'running'
      AND NEW."lease_revision" = OLD."lease_revision"
      AND NEW."lease_updated_at" = OLD."lease_updated_at"
      AND NEW."lease_expires_at" = OLD."lease_expires_at"
      AND OLD."as_of" IS NULL AND NEW."as_of" IS NOT NULL
      AND NEW."as_of" >= OLD."started_at"
      AND NEW."as_of" <= NEW."updated_at"
      AND NEW."source_count" IS NULL
      AND NEW."completed_at" IS NULL)
    -- Seal immutable source and planned-decision manifests.
    OR (OLD."status" = 'running' AND NEW."status" = 'sealed'
      AND NEW."lease_revision" = OLD."lease_revision"
      AND NEW."lease_updated_at" = OLD."lease_updated_at"
      AND NEW."lease_expires_at" = OLD."lease_expires_at"
      AND NEW."as_of" = OLD."as_of" AND NEW."as_of" IS NOT NULL
      AND OLD."source_count" IS NULL AND NEW."source_count" = 9
      AND NEW."partial_source_count" IS NOT NULL
      AND NEW."source_manifest_sha256" IS NOT NULL
      AND NEW."decision_count" IS NOT NULL
      AND NEW."decision_manifest_sha256" IS NOT NULL
      AND NEW."completed_at" IS NULL
      AND (SELECT count(*) FROM "alert_evaluator_run_source" AS source
            WHERE source."run_id" = OLD."id") = 9
      AND NEW."partial_source_count" = (
        SELECT count(*) FROM "alert_evaluator_run_source" AS source
         WHERE source."run_id" = OLD."id" AND source."status" <> 'complete'
      )
      AND NOT EXISTS (
        SELECT 1 FROM "alert_evaluator_run_source" AS source
         WHERE source."run_id" = OLD."id"
           AND source."recorded_at" > NEW."updated_at"
      )
      AND NOT EXISTS (
        SELECT 1 FROM "alert_evaluator_run_decision" AS decision
         WHERE decision."run_id" = OLD."id"
      ))
    -- Runtime terminal transitions update the matching run in their trigger.
    OR (OLD."status" = 'sealed' AND NEW."status" = 'succeeded'
      AND NEW."lease_revision" = OLD."lease_revision"
      AND NEW."lease_updated_at" = OLD."lease_updated_at"
      AND NEW."lease_expires_at" = OLD."lease_expires_at"
      AND NEW."as_of" = OLD."as_of"
      AND NEW."source_count" = OLD."source_count"
      AND NEW."partial_source_count" = OLD."partial_source_count"
      AND NEW."source_manifest_sha256" = OLD."source_manifest_sha256"
      AND NEW."decision_count" = OLD."decision_count"
      AND NEW."decision_manifest_sha256" = OLD."decision_manifest_sha256"
      AND NEW."completed_at" IS NOT NULL
      AND NEW."watermark_at" = OLD."as_of"
      AND NEW."terminal_runtime_revision" = OLD."lease_revision" + 1
      AND NEW."failure_status" IS NULL
      AND NEW."failure_error_code" IS NULL
      AND EXISTS (
        SELECT 1 FROM "alert_runtime_status" AS runtime
         WHERE runtime."component" = 'evaluator'
           AND runtime."generation" = OLD."runtime_generation"
           AND runtime."revision" = NEW."terminal_runtime_revision"
           AND runtime."lease_id" IS NULL
           AND runtime."status" = 'healthy'
           AND runtime."last_success_at" = NEW."completed_at"
           AND runtime."watermark_at" = NEW."watermark_at"
      ))
    OR (OLD."status" IN ('running', 'sealed') AND NEW."status" = 'failed'
      AND NEW."lease_revision" = OLD."lease_revision"
      AND NEW."lease_updated_at" = OLD."lease_updated_at"
      AND NEW."lease_expires_at" = OLD."lease_expires_at"
      AND NEW."as_of" IS OLD."as_of"
      AND NEW."source_count" IS OLD."source_count"
      AND NEW."partial_source_count" IS OLD."partial_source_count"
      AND NEW."source_manifest_sha256" IS OLD."source_manifest_sha256"
      AND NEW."decision_count" IS OLD."decision_count"
      AND NEW."decision_manifest_sha256" IS OLD."decision_manifest_sha256"
      AND NEW."completed_at" IS NOT NULL
      AND NEW."watermark_at" IS NULL
      AND NEW."terminal_runtime_revision" = OLD."lease_revision" + 1
      AND NEW."failure_status" IS NOT NULL
      AND NEW."failure_error_code" IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM "alert_runtime_status" AS runtime
         WHERE runtime."component" = 'evaluator'
           AND runtime."generation" = OLD."runtime_generation"
           AND runtime."revision" = NEW."terminal_runtime_revision"
           AND runtime."lease_id" IS NULL
           AND runtime."status" = NEW."failure_status"
           AND runtime."last_error_at" = NEW."completed_at"
           AND runtime."last_error_code" = NEW."failure_error_code"
      ))
    -- A later acquisition abandons only the exact expired predecessor.
    OR (OLD."status" IN ('running', 'sealed') AND NEW."status" = 'abandoned'
      AND NEW."lease_revision" = OLD."lease_revision"
      AND NEW."lease_updated_at" = OLD."lease_updated_at"
      AND NEW."lease_expires_at" = OLD."lease_expires_at"
      AND NEW."as_of" IS OLD."as_of"
      AND NEW."source_count" IS OLD."source_count"
      AND NEW."partial_source_count" IS OLD."partial_source_count"
      AND NEW."source_manifest_sha256" IS OLD."source_manifest_sha256"
      AND NEW."decision_count" IS OLD."decision_count"
      AND NEW."decision_manifest_sha256" IS OLD."decision_manifest_sha256"
      AND NEW."completed_at" >= OLD."lease_expires_at"
      AND NEW."watermark_at" IS NULL
      AND NEW."terminal_runtime_revision" IS NULL
      AND NEW."failure_status" IS NULL
      AND NEW."failure_error_code" IS NULL
      AND EXISTS (
        SELECT 1 FROM "alert_runtime_status" AS runtime
         WHERE runtime."component" = OLD."component"
           AND runtime."generation" = OLD."runtime_generation"
           AND runtime."revision" = OLD."lease_revision"
           AND runtime."lease_id" = OLD."lease_id"
           AND runtime."lease_expires_at" = OLD."lease_expires_at"
      ))
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid evaluator run transition');
END;

CREATE TRIGGER "alert_evaluator_run_renew_runtime"
AFTER UPDATE ON "alert_evaluator_run"
WHEN NEW."status" = OLD."status"
  AND NEW."status" IN ('running', 'sealed')
  AND NEW."lease_revision" = OLD."lease_revision" + 1
BEGIN
  UPDATE "alert_runtime_status"
     SET "revision" = NEW."lease_revision",
         "lease_expires_at" = NEW."lease_expires_at",
         "updated_at" = NEW."lease_updated_at"
   WHERE "component" = NEW."component"
     AND "generation" = OLD."runtime_generation"
     AND "revision" = OLD."lease_revision"
     AND "lease_id" = OLD."lease_id"
     AND "lease_expires_at" = OLD."lease_expires_at"
     AND "last_started_at" = OLD."started_at"
     AND "updated_at" = OLD."lease_updated_at"
     AND "revision" < 9007199254740990
     AND NEW."lease_updated_at" < OLD."lease_expires_at";

  SELECT CASE WHEN changes() <> 1
    THEN RAISE(ABORT, 'evaluator run failed to renew exact runtime lease')
  END;
END;

CREATE TRIGGER "alert_evaluator_run_live_metadata_guard"
AFTER UPDATE ON "alert_evaluator_run"
WHEN NEW."status" IN ('running', 'sealed')
  AND NEW."lease_revision" = OLD."lease_revision"
BEGIN
  SELECT CASE WHEN NEW."updated_at" >= NEW."lease_expires_at" OR NOT EXISTS (
    SELECT 1 FROM "alert_runtime_status" AS runtime
     WHERE runtime."component" = NEW."component"
       AND runtime."generation" = NEW."runtime_generation"
       AND runtime."revision" = NEW."lease_revision"
       AND runtime."lease_id" = NEW."lease_id"
       AND runtime."lease_expires_at" = NEW."lease_expires_at"
       AND runtime."last_started_at" = NEW."started_at"
       AND runtime."updated_at" = NEW."lease_updated_at"
  ) THEN RAISE(ABORT, 'evaluator run metadata requires live runtime lease') END;
END;

CREATE TRIGGER "alert_evaluator_run_delete_guard"
BEFORE DELETE ON "alert_evaluator_run"
BEGIN
  SELECT RAISE(ABORT, 'evaluator run proof is immutable');
END;

CREATE TRIGGER "alert_evaluator_run_source_insert_guard"
BEFORE INSERT ON "alert_evaluator_run_source"
WHEN NOT EXISTS (
  SELECT 1
    FROM "alert_evaluator_run" AS run
    JOIN "alert_runtime_status" AS runtime
      ON runtime."component" = run."component"
   WHERE run."id" = NEW."run_id"
     AND run."status" = 'running'
     AND run."as_of" = NEW."as_of"
     AND run."runtime_generation" = NEW."runtime_generation"
     AND run."lease_revision" = NEW."runtime_revision"
     AND NEW."recorded_at" >= run."as_of"
     AND NEW."recorded_at" < run."lease_expires_at"
     AND runtime."generation" = run."runtime_generation"
     AND runtime."revision" = run."lease_revision"
     AND runtime."lease_id" = run."lease_id"
     AND runtime."lease_expires_at" = run."lease_expires_at"
)
BEGIN
  SELECT RAISE(ABORT, 'evaluator source proof requires exact live run');
END;

CREATE TRIGGER "alert_evaluator_run_source_conflict_guard"
BEFORE INSERT ON "alert_evaluator_run_source"
WHEN EXISTS (
  SELECT 1 FROM "alert_evaluator_run_source"
   WHERE "run_id" = NEW."run_id" AND "source_id" = NEW."source_id"
)
BEGIN
  SELECT RAISE(ABORT, 'evaluator source proof is immutable');
END;

CREATE TRIGGER "alert_evaluator_run_source_update_guard"
BEFORE UPDATE ON "alert_evaluator_run_source"
BEGIN
  SELECT RAISE(ABORT, 'evaluator source proof is immutable');
END;

CREATE TRIGGER "alert_evaluator_run_source_delete_guard"
BEFORE DELETE ON "alert_evaluator_run_source"
BEGIN
  SELECT RAISE(ABORT, 'evaluator source proof is immutable');
END;

CREATE TRIGGER "alert_evaluator_run_decision_insert_guard"
BEFORE INSERT ON "alert_evaluator_run_decision"
WHEN NOT EXISTS (
  SELECT 1
    FROM "alert_evaluator_run" AS run
    JOIN "alert_runtime_status" AS runtime
      ON runtime."component" = run."component"
   WHERE run."id" = NEW."run_id"
     AND run."status" = 'sealed'
     AND run."as_of" = NEW."as_of"
     AND run."runtime_generation" = NEW."runtime_generation"
     AND run."lease_revision" = NEW."runtime_revision"
     AND NEW."ordinal" < run."decision_count"
     AND NEW."recorded_at" >= run."updated_at"
     AND NEW."recorded_at" < run."lease_expires_at"
     AND runtime."generation" = run."runtime_generation"
     AND runtime."revision" = run."lease_revision"
     AND runtime."lease_id" = run."lease_id"
     AND runtime."lease_expires_at" = run."lease_expires_at"
     AND (
       NEW."disposition" IN ('no_state_change', 'suppressed_partial')
       OR EXISTS (
         SELECT 1 FROM "alert_state" AS state
          WHERE state."id" = NEW."state_id"
            AND state."generation" = NEW."state_generation"
            AND state."revision" = NEW."state_revision"
            AND state."last_evaluated_at" = NEW."as_of"
       )
     )
     AND (
       NEW."disposition" <> 'suppressed_partial'
       OR EXISTS (
         SELECT 1 FROM "alert_evaluator_run_source" AS source
          WHERE source."run_id" = NEW."run_id"
            AND source."source_id" = NEW."source_id"
            AND source."status" = 'partial'
       )
     )
)
BEGIN
  SELECT RAISE(ABORT, 'evaluator decision proof requires exact live run result');
END;

CREATE TRIGGER "alert_evaluator_run_decision_conflict_guard"
BEFORE INSERT ON "alert_evaluator_run_decision"
WHEN EXISTS (
  SELECT 1 FROM "alert_evaluator_run_decision"
   WHERE ("run_id" = NEW."run_id" AND "ordinal" = NEW."ordinal")
      OR ("run_id" = NEW."run_id"
        AND "identity_sha256" = NEW."identity_sha256")
)
BEGIN
  SELECT RAISE(ABORT, 'evaluator decision proof is immutable');
END;

CREATE TRIGGER "alert_evaluator_run_decision_update_guard"
BEFORE UPDATE ON "alert_evaluator_run_decision"
BEGIN
  SELECT RAISE(ABORT, 'evaluator decision proof is immutable');
END;

CREATE TRIGGER "alert_evaluator_run_decision_delete_guard"
BEFORE DELETE ON "alert_evaluator_run_decision"
BEGIN
  SELECT RAISE(ABORT, 'evaluator decision proof is immutable');
END;

-- A terminal runtime transition is accepted only for the exact live run. The
-- AFTER trigger terminalizes that run inside the same SQLite statement.
CREATE TRIGGER "alert_runtime_evaluator_terminal_run_guard"
BEFORE UPDATE ON "alert_runtime_status"
WHEN OLD."component" = 'evaluator'
  AND OLD."lease_id" IS NOT NULL
  AND NEW."lease_id" IS NULL
  AND NOT (
    (NEW."status" = 'healthy' AND EXISTS (
      SELECT 1
        FROM "alert_evaluator_run" AS run
       WHERE run."component" = 'evaluator'
         AND run."status" = 'sealed'
         AND run."runtime_generation" = OLD."generation"
         AND run."lease_revision" = OLD."revision"
         AND run."lease_id" = OLD."lease_id"
         AND run."lease_expires_at" = OLD."lease_expires_at"
         AND run."started_at" = OLD."last_started_at"
         AND run."as_of" = NEW."watermark_at"
         AND run."source_count" = 9
         AND run."partial_source_count" = 0
         AND NEW."revision" = run."lease_revision" + 1
         AND NEW."last_success_at" = NEW."updated_at"
         AND NEW."updated_at" < OLD."lease_expires_at"
         AND NEW."updated_at" > run."updated_at"
         AND (SELECT count(*) FROM "alert_evaluator_run_source" AS source
               WHERE source."run_id" = run."id") = 9
         AND NOT EXISTS (
           SELECT 1 FROM "alert_evaluator_run_source" AS source
            WHERE source."run_id" = run."id" AND source."status" <> 'complete'
         )
         AND NOT EXISTS (
           SELECT 1 FROM "alert_evaluator_run_source" AS source
            WHERE source."run_id" = run."id"
              AND source."recorded_at" >= NEW."updated_at"
         )
         AND (SELECT count(*) FROM "alert_evaluator_run_decision" AS decision
               WHERE decision."run_id" = run."id") = run."decision_count"
         AND NOT EXISTS (
           SELECT 1 FROM "alert_evaluator_run_decision" AS decision
            WHERE decision."run_id" = run."id"
              AND (decision."disposition" = 'suppressed_partial'
                OR decision."recorded_at" >= NEW."updated_at")
         )
    ))
    OR (NEW."status" IN ('degraded', 'failing', 'unavailable') AND EXISTS (
      SELECT 1
        FROM "alert_evaluator_run" AS run
       WHERE run."component" = 'evaluator'
         AND run."status" IN ('running', 'sealed')
         AND run."runtime_generation" = OLD."generation"
         AND run."lease_revision" = OLD."revision"
         AND run."lease_id" = OLD."lease_id"
         AND run."lease_expires_at" = OLD."lease_expires_at"
         AND run."started_at" = OLD."last_started_at"
         AND NEW."revision" = run."lease_revision" + 1
         AND NEW."last_error_at" = NEW."updated_at"
         AND (
           (NEW."status" = 'degraded'
             AND NEW."last_error_code" = 'source_incomplete')
           OR (NEW."status" = 'unavailable'
             AND NEW."last_error_code" = 'metrics_unavailable')
           OR (NEW."status" = 'failing'
             AND NEW."last_error_code" IN ('evaluator_failed', 'unknown'))
         )
         AND NEW."updated_at" < OLD."lease_expires_at"
         AND NEW."updated_at" > run."updated_at"
         AND NOT EXISTS (
           SELECT 1 FROM "alert_evaluator_run_source" AS source
            WHERE source."run_id" = run."id"
              AND source."recorded_at" >= NEW."updated_at"
         )
         AND NOT EXISTS (
           SELECT 1 FROM "alert_evaluator_run_decision" AS decision
            WHERE decision."run_id" = run."id"
              AND decision."recorded_at" >= NEW."updated_at"
         )
    ))
  )
BEGIN
  SELECT RAISE(ABORT, 'evaluator terminal runtime requires exact run proof');
END;

CREATE TRIGGER "alert_runtime_evaluator_terminalize_run"
AFTER UPDATE ON "alert_runtime_status"
WHEN OLD."component" = 'evaluator'
  AND OLD."lease_id" IS NOT NULL
  AND NEW."lease_id" IS NULL
BEGIN
  UPDATE "alert_evaluator_run"
     SET "status" = CASE
           WHEN NEW."status" = 'healthy' THEN 'succeeded' ELSE 'failed'
         END ,
         "completed_at" = NEW."updated_at",
         "watermark_at" = CASE
           WHEN NEW."status" = 'healthy' THEN NEW."watermark_at" ELSE NULL
         END ,
         "terminal_runtime_revision" = NEW."revision",
         "failure_status" = CASE
           WHEN NEW."status" = 'healthy' THEN NULL ELSE NEW."status"
         END ,
         "failure_error_code" = CASE
           WHEN NEW."status" = 'healthy' THEN NULL ELSE NEW."last_error_code"
         END ,
         "updated_at" = NEW."updated_at"
   WHERE "component" = 'evaluator'
     AND "runtime_generation" = OLD."generation"
     AND "lease_revision" = OLD."revision"
     AND "lease_id" = OLD."lease_id"
     AND "status" IN ('running', 'sealed');

  SELECT CASE WHEN changes() <> 1
    THEN RAISE(ABORT, 'evaluator runtime failed to terminalize exact run')
  END;
END;

CREATE INDEX "alert_evaluator_run_status_time_idx"
  ON "alert_evaluator_run" ("status", "updated_at" DESC);

CREATE INDEX "alert_evaluator_run_status_expiry_idx"
  ON "alert_evaluator_run" ("status", "lease_expires_at");

CREATE INDEX "alert_evaluator_run_source_manifest_idx"
  ON "alert_evaluator_run_source" ("run_id", "source_id", "proof_sha256");

CREATE INDEX "alert_evaluator_run_decision_manifest_idx"
  ON "alert_evaluator_run_decision" (
    "run_id", "ordinal", "source_id", "identity_sha256", "decision_sha256"
  );
