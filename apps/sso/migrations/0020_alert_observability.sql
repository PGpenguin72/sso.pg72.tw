-- Redacted alert incident, delivery, and runtime state.
--
-- This migration is deliberately schema-only. It does not enable an evaluator,
-- provision a Queue/provider, or make alert delivery operational. D1 remains
-- authoritative; future Queue messages may carry only opaque delivery handles.
-- Rule IDs below are limited to the reviewed registration/restricted/recovery/
-- Passkey/OAuth-report/admin/audit-fanout/logout/runtime sources. Queue DLQ
-- metrics are explicitly approximate; every other source is exact D1 state.
-- Threshold values remain in versioned rule definitions/tests, not this SQL.
-- Persisted alert timestamps are exact 24-character UTC millisecond strings.
-- Their canonical form makes text ordering precise; SQLite epoch-second
-- conversion drops sub-second ownership and chronology differences.
-- The '+0 seconds' modifier forces calendar normalization. Each formatter
-- result is also checked for non-null because SQLite treats a null CHECK result
-- as passing rather than as a constraint violation.

ALTER TABLE "audit_event" ADD COLUMN "actor_ref" text CHECK (
  "actor_ref" IS NULL
  OR (
    length("actor_ref") = 43
    AND "actor_ref" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("actor_ref", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  )
);

ALTER TABLE "audit_event" ADD COLUMN "actor_ref_hash_version" integer CHECK (
  "actor_ref_hash_version" IS NULL
  OR (typeof("actor_ref_hash_version") = 'integer'
    AND "actor_ref_hash_version" = 1)
);

CREATE TRIGGER "audit_event_actor_ref_insert_guard"
BEFORE INSERT ON "audit_event"
WHEN (NEW."actor_ref" IS NULL) <> (NEW."actor_ref_hash_version" IS NULL)
BEGIN
  SELECT RAISE(ABORT, 'audit actor reference must be paired');
END;

CREATE TRIGGER "audit_event_actor_ref_update_guard"
BEFORE UPDATE OF "actor_ref", "actor_ref_hash_version" ON "audit_event"
WHEN (NEW."actor_ref" IS NULL) <> (NEW."actor_ref_hash_version" IS NULL)
  OR (OLD."actor_ref" IS NULL
    AND NEW."actor_ref" IS NOT NULL
    AND (OLD."actor_user_id" IS NULL
      OR NEW."actor_user_id" IS NOT OLD."actor_user_id"))
  OR (OLD."actor_ref" IS NOT NULL AND (
    NEW."actor_ref" IS NOT OLD."actor_ref"
    OR NEW."actor_ref_hash_version" IS NOT OLD."actor_ref_hash_version"
  ))
BEGIN
  SELECT RAISE(ABORT, 'audit actor reference must be paired');
END;

CREATE TRIGGER "audit_event_actor_identity_update_guard"
BEFORE UPDATE OF "actor_user_id" ON "audit_event"
WHEN NOT (
  NEW."actor_user_id" IS OLD."actor_user_id"
  OR (OLD."actor_user_id" IS NOT NULL AND NEW."actor_user_id" IS NULL)
)
BEGIN
  SELECT RAISE(ABORT, 'audit actor identity cannot be reassigned');
END;

ALTER TABLE "oauth_client_report" ADD COLUMN "reporter_ref" text CHECK (
  "reporter_ref" IS NULL
  OR (
    length("reporter_ref") = 43
    AND "reporter_ref" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("reporter_ref", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  )
);

ALTER TABLE "oauth_client_report"
  ADD COLUMN "reporter_ref_hash_version" integer CHECK (
    "reporter_ref_hash_version" IS NULL
    OR (typeof("reporter_ref_hash_version") = 'integer'
      AND "reporter_ref_hash_version" = 1)
  );

CREATE TRIGGER "oauth_client_report_ref_insert_guard"
BEFORE INSERT ON "oauth_client_report"
WHEN (NEW."reporter_ref" IS NULL) <> (NEW."reporter_ref_hash_version" IS NULL)
BEGIN
  SELECT RAISE(ABORT, 'OAuth reporter reference must be paired');
END;

CREATE TRIGGER "oauth_client_report_ref_update_guard"
BEFORE UPDATE OF "reporter_ref", "reporter_ref_hash_version"
ON "oauth_client_report"
WHEN (NEW."reporter_ref" IS NULL) <> (NEW."reporter_ref_hash_version" IS NULL)
  OR (OLD."reporter_ref" IS NULL
    AND NEW."reporter_ref" IS NOT NULL
    AND (OLD."reporter_user_id" IS NULL
      OR NEW."reporter_user_id" IS NOT OLD."reporter_user_id"))
  OR (OLD."reporter_ref" IS NOT NULL AND (
    NEW."reporter_ref" IS NOT OLD."reporter_ref"
    OR NEW."reporter_ref_hash_version" IS NOT OLD."reporter_ref_hash_version"
  ))
BEGIN
  SELECT RAISE(ABORT, 'OAuth reporter reference must be paired');
END;

CREATE TRIGGER "oauth_client_report_identity_update_guard"
BEFORE UPDATE OF "reporter_user_id" ON "oauth_client_report"
WHEN NOT (
  NEW."reporter_user_id" IS OLD."reporter_user_id"
  OR (OLD."reporter_user_id" IS NOT NULL AND NEW."reporter_user_id" IS NULL)
)
BEGIN
  SELECT RAISE(ABORT, 'OAuth reporter identity cannot be reassigned');
END;

CREATE TABLE "alert_hash_key_sentinel" (
  "id" integer PRIMARY KEY NOT NULL
    CHECK (typeof("id") = 'integer' AND "id" = 1),
  "domain" text NOT NULL
    CHECK ("domain" = 'pgid.alert_subject_hash_key.v1'),
  "fingerprint_ref" text NOT NULL CHECK (
    length("fingerprint_ref") = 43
    AND "fingerprint_ref" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("fingerprint_ref", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  ),
  "hash_version" integer NOT NULL
    CHECK (typeof("hash_version") = 'integer' AND "hash_version" = 1),
  "created_at" date NOT NULL CHECK (
    typeof("created_at") = 'text'
    AND length("created_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds') IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds')
      = "created_at"
  )
);

CREATE TRIGGER "alert_hash_key_sentinel_insert_guard"
BEFORE INSERT ON "alert_hash_key_sentinel"
WHEN EXISTS (SELECT 1 FROM "alert_hash_key_sentinel")
BEGIN
  SELECT RAISE(ABORT, 'alert hash-key sentinel is immutable');
END;

CREATE TRIGGER "alert_hash_key_sentinel_update_guard"
BEFORE UPDATE ON "alert_hash_key_sentinel"
BEGIN
  SELECT RAISE(ABORT, 'alert hash-key sentinel is immutable');
END;

CREATE TRIGGER "alert_hash_key_sentinel_delete_guard"
BEFORE DELETE ON "alert_hash_key_sentinel"
BEGIN
  SELECT RAISE(ABORT, 'alert hash-key sentinel is immutable');
END;

CREATE TABLE "alert_state" (
  "id" text PRIMARY KEY NOT NULL CHECK (length("id") = 36),
  "rule_id" text NOT NULL CHECK (
    "rule_id" IN (
      'pgid.registration.rate_limited.v1',
      'pgid.registration.denied.v1',
      'pgid.registration.challenge_unavailable.v1',
      'pgid.registration.restricted_created.v1',
      'pgid.restricted.sensitive_denied.v1',
      'pgid.recovery.entry_abuse.v1',
      'pgid.recovery.passkey_failure.v1',
      'pgid.passkey.step_up_failure.v1',
      'pgid.oauth.client_report.v1',
      'pgid.admin.sensitive_activity.v1',
      'pgid.admin.directory_volume.v1',
      'pgid.security.fanout_gap.v1',
      'pgid.logout.delivery_health.v1',
      'pgid.alert.runtime_health.v1',
      'pgid.queue.dlq_approximate.v1'
    )
  ),
  "environment" text NOT NULL
    CHECK ("environment" IN ('local', 'preview', 'production')),
  "source_kind" text NOT NULL
    CHECK ("source_kind" IN ('d1_exact', 'queue_approximate')),
  "dedupe_key" text NOT NULL UNIQUE CHECK (
    length("dedupe_key") = 43
    AND "dedupe_key" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("dedupe_key", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  ),
  "subject_ref" text CHECK (
    "subject_ref" IS NULL
    OR (
      length("subject_ref") = 43
      AND "subject_ref" NOT GLOB '*[^A-Za-z0-9_-]*'
      AND substr("subject_ref", -1) IN (
        'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
        'g', 'k', 'o', 's', 'w', '0', '4', '8'
      )
    )
  ),
  "hash_version" integer CHECK ("hash_version" IS NULL OR "hash_version" = 1),
  "provider" text CHECK (
    "provider" IS NULL
    OR "provider" IN (
      'google', 'discord', 'github', 'facebook', 'apple', 'telegram',
      'passkey', 'recovery'
    )
  ),
  "queue_name" text CHECK (
    "queue_name" IS NULL
    OR "queue_name" IN (
      'security_events', 'security_events_dlq',
      'logout_deliveries', 'logout_deliveries_dlq',
      'alert_deliveries', 'alert_deliveries_dlq',
      'audit_archive', 'audit_archive_dlq'
    )
  ),
  "reason" text CHECK (
    "reason" IS NULL
    OR "reason" IN (
      'rate_limited', 'denied', 'unavailable', 'invalid_state',
      'invalid_nonce', 'replay', 'timeout', 'backlog', 'dead_letter',
      'decrypt_failed', 'inconsistent', 'expired', 'rotation_failed',
      'delivery_failed', 'unknown'
    )
  ),
  "surface" text CHECK (
    "surface" IS NULL
    OR "surface" IN (
      'registration', 'login', 'oidc_authorize', 'oidc_token',
      'passkey', 'recovery', 'admin', 'audit', 'logout',
      'alert_delivery', 'archive'
    )
  ),
  "window_seconds" integer NOT NULL
    CHECK ("window_seconds" IN (300, 900, 3600)),
  "metric_name" text NOT NULL CHECK (
    "metric_name" IN (
      'count', 'ratio', 'rate_limited', 'high_risk_count', 'successes',
      'protected_denials', 'missing', 'dead',
      'oldest_unresolved_age_seconds', 'lease_expired', 'evaluator_missing',
      'evaluator_age_seconds', 'outbox_due_age_seconds', 'dead_outbox',
      'depth', 'consecutive_nonzero_samples'
    )
  ),
  "metric_kind" text NOT NULL CHECK (
    "metric_kind" IN ('count', 'ratio', 'age_seconds', 'consecutive', 'boolean')
  ),
  "metric_unit" text NOT NULL CHECK (
    "metric_unit" IN ('events', 'basis_points', 'seconds', 'samples', 'state')
  ),
  "observed_value" integer NOT NULL
    CHECK ("observed_value" BETWEEN 0 AND 1000000000),
  "observed_numerator" integer CHECK (
    "observed_numerator" IS NULL
    OR "observed_numerator" BETWEEN 0 AND 1000000
  ),
  "observed_denominator" integer CHECK (
    "observed_denominator" IS NULL
    OR "observed_denominator" BETWEEN 1 AND 1000000
  ),
  "minimum_sample_count" integer NOT NULL DEFAULT 0
    CHECK ("minimum_sample_count" BETWEEN 0 AND 1000000),
  "minimum_numerator_count" integer CHECK (
    "minimum_numerator_count" IS NULL
    OR "minimum_numerator_count" BETWEEN 1 AND 1000000
  ),
  "warning_threshold" integer CHECK (
    "warning_threshold" IS NULL OR "warning_threshold" BETWEEN 1 AND 1000000000
  ),
  "critical_threshold" integer CHECK (
    "critical_threshold" IS NULL
    OR "critical_threshold" BETWEEN 1 AND 1000000000
  ),
  "secondary_metric_name" text CHECK (
    "secondary_metric_name" IS NULL
    OR "secondary_metric_name" IN ('known_surfaces', 'distinct_reporters')
  ),
  "secondary_metric_kind" text CHECK (
    "secondary_metric_kind" IS NULL OR "secondary_metric_kind" = 'count'
  ),
  "secondary_metric_unit" text CHECK (
    "secondary_metric_unit" IS NULL OR "secondary_metric_unit" = 'events'
  ),
  "secondary_observed_value" integer CHECK (
    "secondary_observed_value" IS NULL
    OR "secondary_observed_value" BETWEEN 0 AND 1000000000
  ),
  "secondary_threshold" integer CHECK (
    "secondary_threshold" IS NULL
    OR "secondary_threshold" BETWEEN 1 AND 1000000000
  ),
  "consecutive_breaches" integer NOT NULL DEFAULT 0
    CHECK ("consecutive_breaches" BETWEEN 0 AND 1),
  "breach_severity" text CHECK (
    "breach_severity" IS NULL OR "breach_severity" IN ('warning', 'critical')
  ),
  "consecutive_clears" integer NOT NULL DEFAULT 0
    CHECK ("consecutive_clears" BETWEEN 0 AND 10000),
  "current_severity" text NOT NULL DEFAULT 'none'
    CHECK ("current_severity" IN ('none', 'warning', 'critical')),
  "generation" integer NOT NULL DEFAULT 0
    CHECK ("generation" BETWEEN 0 AND 1000000),
  "revision" integer NOT NULL DEFAULT 0
    CHECK ("revision" BETWEEN 0 AND 1000000000),
  "cooldown_until" date CHECK (
    "cooldown_until" IS NULL
    OR (typeof("cooldown_until") = 'text'
      AND length("cooldown_until") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "cooldown_until", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "cooldown_until", '+0 seconds'
      )
        = "cooldown_until")
  ),
  "last_evaluated_at" date NOT NULL CHECK (
    typeof("last_evaluated_at") = 'text'
    AND length("last_evaluated_at") = 24
    AND strftime(
      '%Y-%m-%dT%H:%M:%fZ', "last_evaluated_at", '+0 seconds'
    ) IS NOT NULL
    AND strftime(
      '%Y-%m-%dT%H:%M:%fZ', "last_evaluated_at", '+0 seconds'
    )
      = "last_evaluated_at"
  ),
  "last_breached_at" date CHECK (
    "last_breached_at" IS NULL
    OR (typeof("last_breached_at") = 'text'
      AND length("last_breached_at") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_breached_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_breached_at", '+0 seconds'
      )
        = "last_breached_at")
  ),
  "last_cleared_at" date CHECK (
    "last_cleared_at" IS NULL
    OR (typeof("last_cleared_at") = 'text'
      AND length("last_cleared_at") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_cleared_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_cleared_at", '+0 seconds'
      )
        = "last_cleared_at")
  ),
  "last_notification_scheduled_at" date CHECK (
    "last_notification_scheduled_at" IS NULL
    OR (typeof("last_notification_scheduled_at") = 'text'
      AND length("last_notification_scheduled_at") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_notification_scheduled_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_notification_scheduled_at", '+0 seconds'
      )
        = "last_notification_scheduled_at")
  ),
  "created_at" date NOT NULL CHECK (
    typeof("created_at") = 'text'
    AND length("created_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds') IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds')
      = "created_at"
  ),
  "updated_at" date NOT NULL CHECK (
    typeof("updated_at") = 'text'
    AND length("updated_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "updated_at", '+0 seconds') IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "updated_at", '+0 seconds')
      = "updated_at"
  ),
  UNIQUE ("id", "rule_id", "environment", "source_kind"),
  CHECK (
    typeof("window_seconds") = 'integer'
    AND typeof("observed_value") = 'integer'
    AND ("observed_numerator" IS NULL
      OR typeof("observed_numerator") = 'integer')
    AND ("observed_denominator" IS NULL
      OR typeof("observed_denominator") = 'integer')
    AND typeof("minimum_sample_count") = 'integer'
    AND ("minimum_numerator_count" IS NULL
      OR typeof("minimum_numerator_count") = 'integer')
    AND ("warning_threshold" IS NULL
      OR typeof("warning_threshold") = 'integer')
    AND ("critical_threshold" IS NULL
      OR typeof("critical_threshold") = 'integer')
    AND ("secondary_observed_value" IS NULL
      OR typeof("secondary_observed_value") = 'integer')
    AND ("secondary_threshold" IS NULL
      OR typeof("secondary_threshold") = 'integer')
    AND typeof("consecutive_breaches") = 'integer'
    AND typeof("consecutive_clears") = 'integer'
    AND typeof("generation") = 'integer'
    AND typeof("revision") = 'integer'
    AND ("hash_version" IS NULL OR typeof("hash_version") = 'integer')
  ),
  CHECK (
    ("subject_ref" IS NULL AND "hash_version" IS NULL)
    OR ("subject_ref" IS NOT NULL AND "hash_version" IS 1)
  ),
  -- The canonical evaluator has only global, hashed-subject/client/actor, and
  -- Queue dimensions. These reserved context columns remain null until a
  -- versioned rule explicitly adds one to its dimension contract.
  CHECK ("provider" IS NULL AND "reason" IS NULL AND "surface" IS NULL),
  CHECK (
    ("rule_id" IN (
        'pgid.restricted.sensitive_denied.v1',
        'pgid.oauth.client_report.v1',
        'pgid.admin.sensitive_activity.v1',
        'pgid.admin.directory_volume.v1'
      )
      AND "subject_ref" IS NOT NULL
      AND "queue_name" IS NULL)
    OR ("rule_id" IN (
        'pgid.recovery.passkey_failure.v1',
        'pgid.passkey.step_up_failure.v1',
        'pgid.logout.delivery_health.v1'
      )
      AND "queue_name" IS NULL)
    OR ("rule_id" = 'pgid.queue.dlq_approximate.v1'
      AND "subject_ref" IS NULL
      AND "queue_name" IN (
        'security_events_dlq', 'logout_deliveries_dlq',
        'alert_deliveries_dlq', 'audit_archive_dlq'
      ))
    OR ("rule_id" NOT IN (
        'pgid.restricted.sensitive_denied.v1',
        'pgid.oauth.client_report.v1',
        'pgid.admin.sensitive_activity.v1',
        'pgid.admin.directory_volume.v1',
        'pgid.recovery.passkey_failure.v1',
        'pgid.passkey.step_up_failure.v1',
        'pgid.logout.delivery_health.v1',
        'pgid.queue.dlq_approximate.v1'
      )
      AND "subject_ref" IS NULL
      AND "queue_name" IS NULL)
  ),
  CHECK (
    ("rule_id" = 'pgid.queue.dlq_approximate.v1'
      AND "source_kind" = 'queue_approximate')
    OR ("rule_id" <> 'pgid.queue.dlq_approximate.v1'
      AND "source_kind" = 'd1_exact')
  ),
  CHECK (
    ("metric_name" = 'ratio'
      AND "metric_kind" = 'ratio'
      AND "metric_unit" = 'basis_points')
    OR ("metric_name" IN (
        'oldest_unresolved_age_seconds', 'evaluator_age_seconds',
        'outbox_due_age_seconds'
      )
      AND "metric_kind" = 'age_seconds'
      AND "metric_unit" = 'seconds')
    OR ("metric_name" = 'evaluator_missing'
      AND "metric_kind" = 'boolean'
      AND "metric_unit" = 'state')
    OR ("metric_name" = 'consecutive_nonzero_samples'
      AND "metric_kind" = 'consecutive'
      AND "metric_unit" = 'samples')
    OR ("metric_name" IN (
        'count', 'rate_limited', 'high_risk_count', 'successes',
        'protected_denials', 'missing', 'dead', 'lease_expired',
        'dead_outbox', 'depth'
      )
      AND "metric_kind" = 'count'
      AND "metric_unit" = 'events')
  ),
  CHECK (
    ("rule_id" = 'pgid.registration.rate_limited.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.registration.denied.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.registration.challenge_unavailable.v1'
      AND "metric_name" = 'ratio')
    OR ("rule_id" = 'pgid.registration.restricted_created.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.restricted.sensitive_denied.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.recovery.entry_abuse.v1'
      AND "metric_name" IN ('rate_limited', 'ratio'))
    OR ("rule_id" = 'pgid.recovery.passkey_failure.v1'
      AND "metric_name" = 'ratio')
    OR ("rule_id" = 'pgid.passkey.step_up_failure.v1'
      AND "metric_name" = 'ratio')
    OR ("rule_id" = 'pgid.oauth.client_report.v1'
      AND "metric_name" IN ('count', 'high_risk_count'))
    OR ("rule_id" = 'pgid.admin.sensitive_activity.v1'
      AND "metric_name" IN ('count', 'successes', 'protected_denials'))
    OR ("rule_id" = 'pgid.admin.directory_volume.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.logout.delivery_health.v1'
      AND "metric_name" IN (
        'dead', 'oldest_unresolved_age_seconds', 'lease_expired', 'ratio'
      ))
    OR ("rule_id" = 'pgid.alert.runtime_health.v1'
      AND "metric_name" IN (
        'evaluator_missing', 'evaluator_age_seconds',
        'outbox_due_age_seconds', 'dead_outbox'
      ))
    OR ("rule_id" = 'pgid.security.fanout_gap.v1'
      AND "metric_name" = 'missing')
    OR ("rule_id" = 'pgid.queue.dlq_approximate.v1'
      AND "metric_name" IN ('depth', 'consecutive_nonzero_samples'))
  ),
  CHECK (
    ("metric_kind" = 'count'
      AND "metric_unit" = 'events'
      AND "observed_numerator" IS NULL
      AND "observed_denominator" IS NULL
      AND "minimum_sample_count" = 0
      AND "minimum_numerator_count" IS NULL)
    OR ("metric_kind" = 'ratio'
      AND "metric_unit" = 'basis_points'
      AND "observed_numerator" IS NOT NULL
      AND "observed_denominator" IS NOT NULL
      AND "minimum_numerator_count" IS NOT NULL
      AND "minimum_numerator_count" <= "observed_numerator"
      AND "minimum_numerator_count" <= "observed_denominator"
      AND "observed_numerator" <= "observed_denominator"
      AND "observed_denominator" >= "minimum_sample_count"
      AND "observed_value" =
        ("observed_numerator" * 10000) / "observed_denominator")
    OR ("metric_kind" = 'age_seconds'
      AND "metric_unit" = 'seconds'
      AND "observed_numerator" IS NULL
      AND "observed_denominator" IS NULL
      AND "minimum_sample_count" = 0
      AND "minimum_numerator_count" IS NULL)
    OR ("metric_kind" = 'consecutive'
      AND "metric_unit" = 'samples'
      AND "observed_numerator" IS NULL
      AND "observed_denominator" IS NULL
      AND "minimum_sample_count" = 0
      AND "minimum_numerator_count" IS NULL)
    OR ("metric_kind" = 'boolean'
      AND "metric_unit" = 'state'
      AND "observed_value" IN (0, 1)
      AND "observed_numerator" IS NULL
      AND "observed_denominator" IS NULL
      AND "minimum_sample_count" = 0
      AND "minimum_numerator_count" IS NULL)
  ),
  CHECK (
    ("secondary_metric_name" IS NULL
      AND "secondary_metric_kind" IS NULL
      AND "secondary_metric_unit" IS NULL
      AND "secondary_observed_value" IS NULL
      AND "secondary_threshold" IS NULL)
    OR ("secondary_metric_name" IS NOT NULL
      AND "secondary_metric_kind" = 'count'
      AND "secondary_metric_unit" = 'events'
      AND "secondary_observed_value" IS NOT NULL
      AND "secondary_threshold" IS NOT NULL)
  ),
  CHECK (
    "secondary_metric_name" IS NULL
    OR ("rule_id" = 'pgid.restricted.sensitive_denied.v1'
      AND "metric_name" = 'count'
      AND "secondary_metric_name" = 'known_surfaces')
    OR ("rule_id" = 'pgid.oauth.client_report.v1'
      AND "metric_name" = 'high_risk_count'
      AND "secondary_metric_name" = 'distinct_reporters')
  ),
  CHECK (
    "secondary_metric_name" IS NOT 'known_surfaces'
    OR ("secondary_observed_value" <= "observed_value"
      AND "secondary_observed_value" <= 7)
  ),
  CHECK ("warning_threshold" IS NOT NULL OR "critical_threshold" IS NOT NULL),
  CHECK (
    "warning_threshold" IS NULL
    OR "critical_threshold" IS NULL
    OR "critical_threshold" >= "warning_threshold"
  ),
  CHECK (
    ("breach_severity" = 'critical'
      AND "critical_threshold" IS NOT NULL
      AND "observed_value" >= "critical_threshold")
    OR ("breach_severity" = 'warning'
      AND "warning_threshold" IS NOT NULL
      AND "observed_value" >= "warning_threshold")
    OR ("breach_severity" IS NULL
      AND "current_severity" = 'critical'
      AND "critical_threshold" IS NOT NULL
      AND "observed_value" >= "critical_threshold")
    OR ("breach_severity" IS NULL
      AND "current_severity" = 'warning'
      AND "warning_threshold" IS NOT NULL
      AND "observed_value" >= "warning_threshold")
    OR ("breach_severity" IS NULL
      AND "current_severity" = 'none' AND (
      ("warning_threshold" IS NOT NULL
        AND "observed_value" >= "warning_threshold")
      OR ("critical_threshold" IS NOT NULL
        AND "observed_value" >= "critical_threshold")
    ))
  ),
  CHECK (
    "secondary_metric_name" IS NULL
    OR "secondary_observed_value" >= "secondary_threshold"
  ),
  CHECK (
    ("consecutive_breaches" = 0 AND "breach_severity" IS NULL)
    OR ("consecutive_breaches" > 0 AND "breach_severity" IS NOT NULL)
  ),
  CHECK (
    ("current_severity" = 'critical' AND "breach_severity" IS NULL)
    OR ("current_severity" = 'warning'
      AND ("breach_severity" IS NULL OR "breach_severity" = 'critical'))
    OR "current_severity" = 'none'
  ),
  CHECK ("consecutive_breaches" = 0 OR "consecutive_clears" = 0),
  CHECK (
    "rule_id" <> 'pgid.security.fanout_gap.v1'
    OR "consecutive_clears" = 0
  ),
  CHECK ("current_severity" <> 'none' OR "consecutive_clears" = 0),
  CHECK ("current_severity" = 'none' OR "generation" >= 1),
  CHECK ("current_severity" = 'none' OR "cooldown_until" IS NULL),
  CHECK (
    ("current_severity" = 'none'
      AND "last_notification_scheduled_at" IS NULL)
    OR ("current_severity" IN ('warning', 'critical')
      AND "last_notification_scheduled_at" IS NOT NULL
      AND "last_notification_scheduled_at" >= "created_at"
      AND "last_notification_scheduled_at" <= "updated_at")
  ),
  CHECK ("updated_at" >= "created_at"),
  CHECK ("last_evaluated_at" >= "created_at"),
  CHECK ("last_evaluated_at" <= "updated_at"),
  CHECK (
    "last_breached_at" IS NULL
    OR "last_breached_at" >= "created_at"
  ),
  CHECK (
    "last_cleared_at" IS NULL
    OR "last_cleared_at" >= "created_at"
  )
);

CREATE TRIGGER "alert_state_identity_immutable"
BEFORE UPDATE ON "alert_state"
WHEN NEW."id" <> OLD."id"
  OR NEW."rule_id" <> OLD."rule_id"
  OR NEW."environment" <> OLD."environment"
  OR NEW."source_kind" <> OLD."source_kind"
  OR NEW."dedupe_key" <> OLD."dedupe_key"
  OR NEW."subject_ref" IS NOT OLD."subject_ref"
  OR NEW."hash_version" IS NOT OLD."hash_version"
  OR NEW."provider" IS NOT OLD."provider"
  OR NEW."queue_name" IS NOT OLD."queue_name"
  OR NEW."reason" IS NOT OLD."reason"
  OR NEW."surface" IS NOT OLD."surface"
  OR NEW."created_at" <> OLD."created_at"
BEGIN
  SELECT RAISE(ABORT, 'alert state identity is immutable');
END;

CREATE TRIGGER "alert_state_initial_guard"
BEFORE INSERT ON "alert_state"
WHEN NEW."current_severity" <> 'none'
  OR NEW."generation" <> 0
  OR NEW."revision" <> 0
  OR NEW."consecutive_clears" <> 0
  OR NEW."cooldown_until" IS NOT NULL
  OR NEW."last_notification_scheduled_at" IS NOT NULL
  OR NEW."breach_severity" IS NULL
  OR NEW."consecutive_breaches" <> 1
BEGIN
  SELECT RAISE(ABORT, 'alert state must start inactive');
END;

CREATE TRIGGER "alert_state_transition_guard"
BEFORE UPDATE ON "alert_state"
WHEN NEW."revision" <> OLD."revision" + 1
  OR NEW."updated_at" < OLD."updated_at"
  OR NEW."last_evaluated_at" <= OLD."last_evaluated_at"
  OR (OLD."current_severity" IN ('warning', 'critical')
    AND NEW."current_severity" = 'none'
    AND (
      NEW."cooldown_until" IS NULL
      OR NEW."cooldown_until" <> strftime(
        '%Y-%m-%dT%H:%M:%fZ', NEW."last_evaluated_at", '+1800 seconds'
      )
    ))
  OR (OLD."current_severity" = 'none'
    AND NEW."current_severity" = 'none'
    AND NOT (
      NEW."cooldown_until" IS OLD."cooldown_until"
      OR (OLD."cooldown_until" IS NOT NULL
        AND NEW."cooldown_until" IS NULL
        AND NEW."last_evaluated_at" >= OLD."cooldown_until")
    ))
  OR (OLD."last_notification_scheduled_at" IS NOT NULL
    AND NEW."last_notification_scheduled_at" IS NOT NULL
    AND NEW."last_notification_scheduled_at"
      < OLD."last_notification_scheduled_at")
  OR NOT (
    (OLD."current_severity" = 'none'
      AND NEW."current_severity" = 'none'
      AND NEW."generation" = OLD."generation")
    OR (OLD."current_severity" = 'none'
      AND NEW."current_severity" = 'warning'
      AND NEW."generation" = OLD."generation" + 1
      AND OLD."breach_severity" = 'warning'
      AND OLD."consecutive_breaches" = 1
      AND (OLD."cooldown_until" IS NULL
        OR NEW."last_evaluated_at" >= OLD."cooldown_until")
      AND NEW."breach_severity" IS NULL
      AND NEW."consecutive_breaches" = 0
      AND NEW."consecutive_clears" = 0)
    OR (OLD."current_severity" = 'none'
      AND NEW."current_severity" = 'critical'
      AND NEW."generation" = OLD."generation" + 1
      AND (
        (OLD."breach_severity" = 'critical'
          AND OLD."consecutive_breaches" = 1)
        OR (NEW."rule_id" = 'pgid.logout.delivery_health.v1'
          AND NEW."metric_name" = 'dead')
        OR (NEW."rule_id" = 'pgid.alert.runtime_health.v1'
          AND NEW."metric_name" IN ('evaluator_missing', 'dead_outbox'))
      )
      AND NEW."breach_severity" IS NULL
      AND NEW."consecutive_breaches" = 0
      AND NEW."consecutive_clears" = 0)
    OR (OLD."current_severity" = 'warning'
      AND NEW."current_severity" = 'warning'
      AND NEW."generation" = OLD."generation")
    OR (OLD."current_severity" = 'warning'
      AND NEW."current_severity" = 'critical'
      AND NEW."generation" = OLD."generation"
      AND (
        (OLD."breach_severity" = 'critical'
          AND OLD."consecutive_breaches" = 1)
        OR (NEW."rule_id" = 'pgid.logout.delivery_health.v1'
          AND NEW."metric_name" = 'dead')
        OR (NEW."rule_id" = 'pgid.alert.runtime_health.v1'
          AND NEW."metric_name" IN ('evaluator_missing', 'dead_outbox'))
      )
      AND NEW."breach_severity" IS NULL
      AND NEW."consecutive_breaches" = 0
      AND NEW."consecutive_clears" = 0)
    OR (OLD."current_severity" = 'warning'
      AND NEW."current_severity" = 'none'
      AND NEW."generation" = OLD."generation"
      AND (
        (NEW."rule_id" <> 'pgid.security.fanout_gap.v1'
          AND OLD."consecutive_clears" = 4)
        OR EXISTS (
            SELECT 1
              FROM "security_alert" AS incident
             WHERE incident."state_id" = OLD."id"
               AND incident."generation" = OLD."generation"
               AND incident."status" = 'resolved'
               AND incident."resolved_by_ref" IS NOT NULL
               AND incident."resolved_by_hash_version" = 1
               AND incident."resolution_code" IN (
                 'manual_false_positive', 'approved_test', 'operator_resolved'
               )
          )
      )
      AND NEW."consecutive_clears" = 0
      AND NEW."breach_severity" IS NULL
      AND NEW."consecutive_breaches" = 0)
    OR (OLD."current_severity" = 'critical'
      AND NEW."current_severity" = 'critical'
      AND NEW."generation" = OLD."generation")
    OR (OLD."current_severity" = 'critical'
      AND NEW."current_severity" = 'none'
      AND NEW."generation" = OLD."generation"
      AND (
        (NEW."rule_id" <> 'pgid.security.fanout_gap.v1'
          AND OLD."consecutive_clears" = 4)
        OR EXISTS (
            SELECT 1
              FROM "security_alert" AS incident
             WHERE incident."state_id" = OLD."id"
               AND incident."generation" = OLD."generation"
               AND incident."status" = 'resolved'
               AND incident."resolved_by_ref" IS NOT NULL
               AND incident."resolved_by_hash_version" = 1
               AND incident."resolution_code" IN (
                 'manual_false_positive', 'approved_test', 'operator_resolved'
               )
          )
      )
      AND NEW."consecutive_clears" = 0
      AND NEW."breach_severity" IS NULL
      AND NEW."consecutive_breaches" = 0)
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid alert state transition');
END;

CREATE TRIGGER "alert_state_counter_transition_guard"
BEFORE UPDATE ON "alert_state"
WHEN OLD."current_severity" = NEW."current_severity"
  AND NOT (
    (NEW."breach_severity" IS OLD."breach_severity"
      AND NEW."consecutive_breaches" = OLD."consecutive_breaches"
      AND NEW."consecutive_clears" = OLD."consecutive_clears")
    OR (NEW."breach_severity" IS NOT NULL
      AND NEW."consecutive_breaches" = 1
      AND NEW."consecutive_clears" = 0)
    OR (NEW."breach_severity" IS NULL
      AND NEW."consecutive_breaches" = 0
      AND NEW."consecutive_clears" = 0)
    OR (OLD."current_severity" IN ('warning', 'critical')
      AND NEW."rule_id" <> 'pgid.security.fanout_gap.v1'
      AND OLD."breach_severity" IS NULL
      AND OLD."consecutive_breaches" = 0
      AND NEW."breach_severity" IS NULL
      AND NEW."consecutive_breaches" = 0
      AND NEW."consecutive_clears" = OLD."consecutive_clears" + 1
      AND NEW."consecutive_clears" BETWEEN 1 AND 4)
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid alert state counter transition');
END;

CREATE INDEX "alert_state_evaluation_idx"
  ON "alert_state" ("last_evaluated_at", "rule_id", "environment");

CREATE UNIQUE INDEX "alert_state_semantic_identity_idx"
  ON "alert_state" (
    "rule_id", "environment", "source_kind",
    coalesce("subject_ref", ''), coalesce("queue_name", '')
  );

CREATE TABLE "security_alert" (
  "id" text PRIMARY KEY NOT NULL CHECK (length("id") = 36),
  "state_id" text NOT NULL,
  "rule_id" text NOT NULL,
  "environment" text NOT NULL,
  "generation" integer NOT NULL
    CHECK ("generation" BETWEEN 1 AND 1000000),
  "severity" text NOT NULL CHECK ("severity" IN ('warning', 'critical')),
  "status" text NOT NULL
    CHECK ("status" IN ('open', 'acknowledged', 'resolved')),
  "source_kind" text NOT NULL
    CHECK ("source_kind" IN ('d1_exact', 'queue_approximate')),
  "first_seen_at" date NOT NULL CHECK (
    typeof("first_seen_at") = 'text'
    AND length("first_seen_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "first_seen_at", '+0 seconds')
      IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "first_seen_at", '+0 seconds')
      = "first_seen_at"
  ),
  "last_seen_at" date NOT NULL CHECK (
    typeof("last_seen_at") = 'text'
    AND length("last_seen_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "last_seen_at", '+0 seconds')
      IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "last_seen_at", '+0 seconds')
      = "last_seen_at"
  ),
  "window_seconds" integer NOT NULL
    CHECK ("window_seconds" IN (300, 900, 3600)),
  "metric_name" text NOT NULL CHECK (
    "metric_name" IN (
      'count', 'ratio', 'rate_limited', 'high_risk_count', 'successes',
      'protected_denials', 'missing', 'dead',
      'oldest_unresolved_age_seconds', 'lease_expired', 'evaluator_missing',
      'evaluator_age_seconds', 'outbox_due_age_seconds', 'dead_outbox',
      'depth', 'consecutive_nonzero_samples'
    )
  ),
  "metric_kind" text NOT NULL CHECK (
    "metric_kind" IN ('count', 'ratio', 'age_seconds', 'consecutive', 'boolean')
  ),
  "metric_unit" text NOT NULL CHECK (
    "metric_unit" IN ('events', 'basis_points', 'seconds', 'samples', 'state')
  ),
  "observed_value" integer NOT NULL
    CHECK ("observed_value" BETWEEN 0 AND 1000000000),
  "observed_numerator" integer CHECK (
    "observed_numerator" IS NULL
    OR "observed_numerator" BETWEEN 0 AND 1000000
  ),
  "observed_denominator" integer CHECK (
    "observed_denominator" IS NULL
    OR "observed_denominator" BETWEEN 1 AND 1000000
  ),
  "minimum_sample_count" integer NOT NULL DEFAULT 0
    CHECK ("minimum_sample_count" BETWEEN 0 AND 1000000),
  "minimum_numerator_count" integer CHECK (
    "minimum_numerator_count" IS NULL
    OR "minimum_numerator_count" BETWEEN 1 AND 1000000
  ),
  "threshold" integer NOT NULL CHECK ("threshold" BETWEEN 1 AND 1000000000),
  "secondary_metric_name" text CHECK (
    "secondary_metric_name" IS NULL
    OR "secondary_metric_name" IN ('known_surfaces', 'distinct_reporters')
  ),
  "secondary_metric_kind" text CHECK (
    "secondary_metric_kind" IS NULL OR "secondary_metric_kind" = 'count'
  ),
  "secondary_metric_unit" text CHECK (
    "secondary_metric_unit" IS NULL OR "secondary_metric_unit" = 'events'
  ),
  "secondary_observed_value" integer CHECK (
    "secondary_observed_value" IS NULL
    OR "secondary_observed_value" BETWEEN 0 AND 1000000000
  ),
  "secondary_threshold" integer CHECK (
    "secondary_threshold" IS NULL
    OR "secondary_threshold" BETWEEN 1 AND 1000000000
  ),
  "acknowledged_at" date CHECK (
    "acknowledged_at" IS NULL
    OR (typeof("acknowledged_at") = 'text'
      AND length("acknowledged_at") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "acknowledged_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "acknowledged_at", '+0 seconds'
      )
        = "acknowledged_at")
  ),
  "acknowledged_by_ref" text CHECK (
    "acknowledged_by_ref" IS NULL
    OR (
      length("acknowledged_by_ref") = 43
      AND "acknowledged_by_ref" NOT GLOB '*[^A-Za-z0-9_-]*'
      AND substr("acknowledged_by_ref", -1) IN (
        'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
        'g', 'k', 'o', 's', 'w', '0', '4', '8'
      )
    )
  ),
  "acknowledged_by_hash_version" integer CHECK (
    "acknowledged_by_hash_version" IS NULL
    OR "acknowledged_by_hash_version" = 1
  ),
  "resolved_at" date CHECK (
    "resolved_at" IS NULL
    OR (typeof("resolved_at") = 'text'
      AND length("resolved_at") = 24
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "resolved_at", '+0 seconds')
        IS NOT NULL
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "resolved_at", '+0 seconds')
        = "resolved_at")
  ),
  "resolved_by_ref" text CHECK (
    "resolved_by_ref" IS NULL
    OR (
      length("resolved_by_ref") = 43
      AND "resolved_by_ref" NOT GLOB '*[^A-Za-z0-9_-]*'
      AND substr("resolved_by_ref", -1) IN (
        'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
        'g', 'k', 'o', 's', 'w', '0', '4', '8'
      )
    )
  ),
  "resolved_by_hash_version" integer CHECK (
    "resolved_by_hash_version" IS NULL OR "resolved_by_hash_version" = 1
  ),
  "resolution_code" text CHECK (
    "resolution_code" IS NULL
    OR "resolution_code" IN (
      'healthy', 'manual_false_positive', 'approved_test', 'operator_resolved'
    )
  ),
  "created_at" date NOT NULL CHECK (
    typeof("created_at") = 'text'
    AND length("created_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds') IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds')
      = "created_at"
  ),
  "updated_at" date NOT NULL CHECK (
    typeof("updated_at") = 'text'
    AND length("updated_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "updated_at", '+0 seconds') IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "updated_at", '+0 seconds')
      = "updated_at"
  ),
  UNIQUE ("state_id", "generation"),
  UNIQUE ("id", "generation"),
  UNIQUE ("id", "generation", "rule_id", "environment", "source_kind"),
  FOREIGN KEY ("state_id", "rule_id", "environment", "source_kind")
    REFERENCES "alert_state" (
      "id", "rule_id", "environment", "source_kind"
    ) ON DELETE RESTRICT,
  CHECK (
    typeof("generation") = 'integer'
    AND typeof("window_seconds") = 'integer'
    AND typeof("observed_value") = 'integer'
    AND ("observed_numerator" IS NULL
      OR typeof("observed_numerator") = 'integer')
    AND ("observed_denominator" IS NULL
      OR typeof("observed_denominator") = 'integer')
    AND typeof("minimum_sample_count") = 'integer'
    AND ("minimum_numerator_count" IS NULL
      OR typeof("minimum_numerator_count") = 'integer')
    AND typeof("threshold") = 'integer'
    AND ("secondary_observed_value" IS NULL
      OR typeof("secondary_observed_value") = 'integer')
    AND ("secondary_threshold" IS NULL
      OR typeof("secondary_threshold") = 'integer')
    AND ("acknowledged_by_hash_version" IS NULL
      OR typeof("acknowledged_by_hash_version") = 'integer')
    AND ("resolved_by_hash_version" IS NULL
      OR typeof("resolved_by_hash_version") = 'integer')
  ),
  CHECK (
    ("metric_name" = 'ratio'
      AND "metric_kind" = 'ratio'
      AND "metric_unit" = 'basis_points')
    OR ("metric_name" IN (
        'oldest_unresolved_age_seconds', 'evaluator_age_seconds',
        'outbox_due_age_seconds'
      )
      AND "metric_kind" = 'age_seconds'
      AND "metric_unit" = 'seconds')
    OR ("metric_name" = 'evaluator_missing'
      AND "metric_kind" = 'boolean'
      AND "metric_unit" = 'state')
    OR ("metric_name" = 'consecutive_nonzero_samples'
      AND "metric_kind" = 'consecutive'
      AND "metric_unit" = 'samples')
    OR ("metric_name" IN (
        'count', 'rate_limited', 'high_risk_count', 'successes',
        'protected_denials', 'missing', 'dead', 'lease_expired',
        'dead_outbox', 'depth'
      )
      AND "metric_kind" = 'count'
      AND "metric_unit" = 'events')
  ),
  CHECK (
    ("rule_id" = 'pgid.registration.rate_limited.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.registration.denied.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.registration.challenge_unavailable.v1'
      AND "metric_name" = 'ratio')
    OR ("rule_id" = 'pgid.registration.restricted_created.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.restricted.sensitive_denied.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.recovery.entry_abuse.v1'
      AND "metric_name" IN ('rate_limited', 'ratio'))
    OR ("rule_id" = 'pgid.recovery.passkey_failure.v1'
      AND "metric_name" = 'ratio')
    OR ("rule_id" = 'pgid.passkey.step_up_failure.v1'
      AND "metric_name" = 'ratio')
    OR ("rule_id" = 'pgid.oauth.client_report.v1'
      AND "metric_name" IN ('count', 'high_risk_count'))
    OR ("rule_id" = 'pgid.admin.sensitive_activity.v1'
      AND "metric_name" IN ('count', 'successes', 'protected_denials'))
    OR ("rule_id" = 'pgid.admin.directory_volume.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.logout.delivery_health.v1'
      AND "metric_name" IN (
        'dead', 'oldest_unresolved_age_seconds', 'lease_expired', 'ratio'
      ))
    OR ("rule_id" = 'pgid.alert.runtime_health.v1'
      AND "metric_name" IN (
        'evaluator_missing', 'evaluator_age_seconds',
        'outbox_due_age_seconds', 'dead_outbox'
      ))
    OR ("rule_id" = 'pgid.security.fanout_gap.v1'
      AND "metric_name" = 'missing')
    OR ("rule_id" = 'pgid.queue.dlq_approximate.v1'
      AND "metric_name" IN ('depth', 'consecutive_nonzero_samples'))
  ),
  CHECK (
    ("metric_kind" = 'count'
      AND "metric_unit" = 'events'
      AND "observed_numerator" IS NULL
      AND "observed_denominator" IS NULL
      AND "minimum_sample_count" = 0
      AND "minimum_numerator_count" IS NULL)
    OR ("metric_kind" = 'ratio'
      AND "metric_unit" = 'basis_points'
      AND "observed_numerator" IS NOT NULL
      AND "observed_denominator" IS NOT NULL
      AND "minimum_numerator_count" IS NOT NULL
      AND "minimum_numerator_count" <= "observed_numerator"
      AND "minimum_numerator_count" <= "observed_denominator"
      AND "observed_numerator" <= "observed_denominator"
      AND "observed_denominator" >= "minimum_sample_count"
      AND "observed_value" =
        ("observed_numerator" * 10000) / "observed_denominator")
    OR ("metric_kind" = 'age_seconds'
      AND "metric_unit" = 'seconds'
      AND "observed_numerator" IS NULL
      AND "observed_denominator" IS NULL
      AND "minimum_sample_count" = 0
      AND "minimum_numerator_count" IS NULL)
    OR ("metric_kind" = 'consecutive'
      AND "metric_unit" = 'samples'
      AND "observed_numerator" IS NULL
      AND "observed_denominator" IS NULL
      AND "minimum_sample_count" = 0
      AND "minimum_numerator_count" IS NULL)
    OR ("metric_kind" = 'boolean'
      AND "metric_unit" = 'state'
      AND "observed_value" IN (0, 1)
      AND "observed_numerator" IS NULL
      AND "observed_denominator" IS NULL
      AND "minimum_sample_count" = 0
      AND "minimum_numerator_count" IS NULL)
  ),
  CHECK (
    ("secondary_metric_name" IS NULL
      AND "secondary_metric_kind" IS NULL
      AND "secondary_metric_unit" IS NULL
      AND "secondary_observed_value" IS NULL
      AND "secondary_threshold" IS NULL)
    OR ("secondary_metric_name" IS NOT NULL
      AND "secondary_metric_kind" = 'count'
      AND "secondary_metric_unit" = 'events'
      AND "secondary_observed_value" IS NOT NULL
      AND "secondary_threshold" IS NOT NULL)
  ),
  CHECK (
    "secondary_metric_name" IS NULL
    OR ("rule_id" = 'pgid.restricted.sensitive_denied.v1'
      AND "metric_name" = 'count'
      AND "secondary_metric_name" = 'known_surfaces')
    OR ("rule_id" = 'pgid.oauth.client_report.v1'
      AND "metric_name" = 'high_risk_count'
      AND "secondary_metric_name" = 'distinct_reporters')
  ),
  CHECK (
    "secondary_metric_name" IS NOT 'known_surfaces'
    OR ("secondary_observed_value" <= "observed_value"
      AND "secondary_observed_value" <= 7)
  ),
  CHECK ("observed_value" >= "threshold"),
  CHECK (
    "secondary_metric_name" IS NULL
    OR "secondary_observed_value" >= "secondary_threshold"
  ),
  CHECK ("last_seen_at" >= "first_seen_at"),
  CHECK ("created_at" <= "first_seen_at"),
  CHECK ("updated_at" >= "created_at"),
  CHECK ("updated_at" >= "last_seen_at"),
  CHECK (
    "acknowledged_at" IS NULL
    OR ("acknowledged_at" >= "created_at"
      AND "acknowledged_at" <= "updated_at")
  ),
  CHECK (
    "resolved_at" IS NULL
    OR ("resolved_at" >= "created_at"
      AND "resolved_at" <= "updated_at")
  ),
  CHECK (
    "acknowledged_at" IS NULL
    OR "resolved_at" IS NULL
    OR "resolved_at" >= "acknowledged_at"
  ),
  CHECK (
    ("acknowledged_at" IS NULL
      AND "acknowledged_by_ref" IS NULL
      AND "acknowledged_by_hash_version" IS NULL)
    OR ("acknowledged_at" IS NOT NULL
      AND "acknowledged_by_ref" IS NOT NULL
      AND "acknowledged_by_hash_version" IS 1)
  ),
  CHECK (
    ("resolved_at" IS NULL AND "resolution_code" IS NULL)
    OR ("resolved_at" IS NOT NULL AND "resolution_code" IS NOT NULL)
  ),
  CHECK ("resolved_by_ref" IS NULL OR "resolved_at" IS NOT NULL),
  CHECK (
    ("resolved_by_ref" IS NULL AND "resolved_by_hash_version" IS NULL)
    OR ("resolved_by_ref" IS NOT NULL AND "resolved_by_hash_version" IS 1)
  ),
  CHECK (
    ("resolution_code" IS NULL AND "resolved_by_ref" IS NULL)
    OR ("resolution_code" = 'healthy' AND "resolved_by_ref" IS NULL)
    OR ("resolution_code" IN (
      'manual_false_positive', 'approved_test', 'operator_resolved'
    ) AND "resolved_by_ref" IS NOT NULL)
  ),
  CHECK (
    "rule_id" <> 'pgid.security.fanout_gap.v1'
    OR "resolution_code" IS NULL
    OR "resolution_code" IN (
      'manual_false_positive', 'approved_test', 'operator_resolved'
    )
  ),
  CHECK (
    ("status" = 'open'
      AND "acknowledged_at" IS NULL
      AND "resolved_at" IS NULL)
    OR ("status" = 'acknowledged'
      AND "acknowledged_at" IS NOT NULL
      AND "resolved_at" IS NULL)
    OR ("status" = 'resolved' AND "resolved_at" IS NOT NULL)
  )
);

CREATE TRIGGER "security_alert_insert_state_guard"
BEFORE INSERT ON "security_alert"
WHEN NEW."status" <> 'open'
  OR NEW."acknowledged_at" IS NOT NULL
  OR NEW."acknowledged_by_ref" IS NOT NULL
  OR NEW."acknowledged_by_hash_version" IS NOT NULL
  OR NEW."resolved_at" IS NOT NULL
  OR NEW."resolved_by_ref" IS NOT NULL
  OR NEW."resolved_by_hash_version" IS NOT NULL
  OR NEW."resolution_code" IS NOT NULL
  OR NOT EXISTS (
  SELECT 1
    FROM "alert_state" AS state
   WHERE state."id" = NEW."state_id"
     AND state."rule_id" = NEW."rule_id"
     AND state."environment" = NEW."environment"
     AND state."source_kind" = NEW."source_kind"
     AND state."generation" = NEW."generation"
     AND state."current_severity" = NEW."severity"
     AND state."breach_severity" IS NULL
     AND state."window_seconds" = NEW."window_seconds"
     AND state."metric_name" = NEW."metric_name"
     AND state."metric_kind" = NEW."metric_kind"
     AND state."metric_unit" = NEW."metric_unit"
     AND state."observed_value" = NEW."observed_value"
     AND state."observed_numerator" IS NEW."observed_numerator"
     AND state."observed_denominator" IS NEW."observed_denominator"
     AND state."minimum_sample_count" = NEW."minimum_sample_count"
     AND state."minimum_numerator_count" IS NEW."minimum_numerator_count"
     AND (
       (NEW."severity" = 'warning'
         AND state."warning_threshold" = NEW."threshold")
       OR (NEW."severity" = 'critical'
         AND state."critical_threshold" = NEW."threshold")
     )
     AND state."secondary_metric_name" IS NEW."secondary_metric_name"
     AND state."secondary_metric_kind" IS NEW."secondary_metric_kind"
     AND state."secondary_metric_unit" IS NEW."secondary_metric_unit"
     AND state."secondary_observed_value" IS NEW."secondary_observed_value"
     AND state."secondary_threshold" IS NEW."secondary_threshold"
)
BEGIN
  SELECT RAISE(ABORT, 'security alert does not match confirmed state');
END;

CREATE TRIGGER "security_alert_update_state_guard"
BEFORE UPDATE ON "security_alert"
WHEN NEW."status" IN ('open', 'acknowledged')
  AND NOT EXISTS (
    SELECT 1
      FROM "alert_state" AS state
     WHERE state."id" = NEW."state_id"
       AND state."rule_id" = NEW."rule_id"
       AND state."environment" = NEW."environment"
       AND state."source_kind" = NEW."source_kind"
       AND state."generation" = NEW."generation"
       AND state."current_severity" = NEW."severity"
       AND state."breach_severity" IS NULL
       AND state."window_seconds" = NEW."window_seconds"
       AND state."metric_name" = NEW."metric_name"
       AND state."metric_kind" = NEW."metric_kind"
       AND state."metric_unit" = NEW."metric_unit"
       AND state."observed_value" = NEW."observed_value"
       AND state."observed_numerator" IS NEW."observed_numerator"
       AND state."observed_denominator" IS NEW."observed_denominator"
       AND state."minimum_sample_count" = NEW."minimum_sample_count"
       AND state."minimum_numerator_count" IS NEW."minimum_numerator_count"
       AND (
         (NEW."severity" = 'warning'
           AND state."warning_threshold" = NEW."threshold")
         OR (NEW."severity" = 'critical'
           AND state."critical_threshold" = NEW."threshold")
       )
       AND state."secondary_metric_name" IS NEW."secondary_metric_name"
       AND state."secondary_metric_kind" IS NEW."secondary_metric_kind"
       AND state."secondary_metric_unit" IS NEW."secondary_metric_unit"
       AND state."secondary_observed_value" IS NEW."secondary_observed_value"
       AND state."secondary_threshold" IS NEW."secondary_threshold"
  )
BEGIN
  SELECT RAISE(ABORT, 'security alert update does not match confirmed state');
END;

CREATE TRIGGER "security_alert_transition_guard"
BEFORE UPDATE ON "security_alert"
WHEN NEW."id" <> OLD."id"
  OR NEW."state_id" <> OLD."state_id"
  OR NEW."rule_id" <> OLD."rule_id"
  OR NEW."environment" <> OLD."environment"
  OR NEW."source_kind" <> OLD."source_kind"
  OR NEW."generation" <> OLD."generation"
  OR NEW."first_seen_at" <> OLD."first_seen_at"
  OR NEW."created_at" <> OLD."created_at"
  OR NEW."updated_at" < OLD."updated_at"
  OR NEW."last_seen_at" < OLD."last_seen_at"
  OR NOT (
    NEW."severity" = OLD."severity"
    OR (OLD."severity" = 'warning' AND NEW."severity" = 'critical')
  )
  OR NOT (
    NEW."status" = OLD."status"
    OR (OLD."status" = 'open'
      AND NEW."status" IN ('acknowledged', 'resolved'))
    OR (OLD."status" = 'acknowledged' AND NEW."status" = 'resolved')
  )
  OR (OLD."status" = 'acknowledged' AND (
    NEW."acknowledged_at" IS NOT OLD."acknowledged_at"
    OR NEW."acknowledged_by_ref" IS NOT OLD."acknowledged_by_ref"
    OR NEW."acknowledged_by_hash_version"
      IS NOT OLD."acknowledged_by_hash_version"
  ))
  OR (NEW."status" = 'resolved' AND (
    NEW."severity" <> OLD."severity"
    OR NEW."last_seen_at" <> OLD."last_seen_at"
    OR NEW."window_seconds" <> OLD."window_seconds"
    OR NEW."metric_name" <> OLD."metric_name"
    OR NEW."metric_kind" <> OLD."metric_kind"
    OR NEW."metric_unit" <> OLD."metric_unit"
    OR NEW."observed_value" <> OLD."observed_value"
    OR NEW."observed_numerator" IS NOT OLD."observed_numerator"
    OR NEW."observed_denominator" IS NOT OLD."observed_denominator"
    OR NEW."minimum_sample_count" <> OLD."minimum_sample_count"
    OR NEW."minimum_numerator_count" IS NOT OLD."minimum_numerator_count"
    OR NEW."threshold" <> OLD."threshold"
    OR NEW."secondary_metric_name" IS NOT OLD."secondary_metric_name"
    OR NEW."secondary_metric_kind" IS NOT OLD."secondary_metric_kind"
    OR NEW."secondary_metric_unit" IS NOT OLD."secondary_metric_unit"
    OR NEW."secondary_observed_value" IS NOT OLD."secondary_observed_value"
    OR NEW."secondary_threshold" IS NOT OLD."secondary_threshold"
  ))
  OR (OLD."status" = 'resolved' AND (
    NEW."severity" <> OLD."severity"
    OR NEW."last_seen_at" <> OLD."last_seen_at"
    OR NEW."window_seconds" <> OLD."window_seconds"
    OR NEW."metric_name" <> OLD."metric_name"
    OR NEW."metric_kind" <> OLD."metric_kind"
    OR NEW."metric_unit" <> OLD."metric_unit"
    OR NEW."observed_value" <> OLD."observed_value"
    OR NEW."observed_numerator" IS NOT OLD."observed_numerator"
    OR NEW."observed_denominator" IS NOT OLD."observed_denominator"
    OR NEW."minimum_sample_count" <> OLD."minimum_sample_count"
    OR NEW."minimum_numerator_count" IS NOT OLD."minimum_numerator_count"
    OR NEW."threshold" <> OLD."threshold"
    OR NEW."secondary_metric_name" IS NOT OLD."secondary_metric_name"
    OR NEW."secondary_metric_kind" IS NOT OLD."secondary_metric_kind"
    OR NEW."secondary_metric_unit" IS NOT OLD."secondary_metric_unit"
    OR NEW."secondary_observed_value" IS NOT OLD."secondary_observed_value"
    OR NEW."secondary_threshold" IS NOT OLD."secondary_threshold"
    OR NEW."acknowledged_at" IS NOT OLD."acknowledged_at"
    OR NEW."acknowledged_by_ref" IS NOT OLD."acknowledged_by_ref"
    OR NEW."acknowledged_by_hash_version"
      IS NOT OLD."acknowledged_by_hash_version"
    OR NEW."resolved_at" IS NOT OLD."resolved_at"
    OR NEW."resolved_by_ref" IS NOT OLD."resolved_by_ref"
    OR NEW."resolved_by_hash_version" IS NOT OLD."resolved_by_hash_version"
    OR NEW."resolution_code" IS NOT OLD."resolution_code"
  ))
BEGIN
  SELECT RAISE(ABORT, 'invalid security alert transition');
END;

-- alert_state.dedupe_key is unique, so one unresolved row per state is exactly
-- one unresolved incident per dedupe key. A resolved generation may coexist.
CREATE UNIQUE INDEX "security_alert_unresolved_state_idx"
  ON "security_alert" ("state_id")
  WHERE "status" IN ('open', 'acknowledged');

CREATE INDEX "security_alert_operator_idx"
  ON "security_alert" ("status", "severity", "updated_at" DESC);

CREATE TABLE "alert_outbox" (
  "id" integer PRIMARY KEY AUTOINCREMENT,
  "delivery_key" text NOT NULL UNIQUE CHECK (
    length("delivery_key") = 51
    AND substr("delivery_key", 1, 8) = 'pgid_ad_'
    AND substr("delivery_key", 9) NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("delivery_key", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  ),
  "alert_id" text NOT NULL,
  "generation" integer NOT NULL
    CHECK ("generation" BETWEEN 1 AND 1000000),
  "event_kind" text NOT NULL
    CHECK ("event_kind" IN ('opened', 'reminder', 'escalated', 'resolved')),
  "event_sequence" integer NOT NULL
    CHECK ("event_sequence" BETWEEN 1 AND 1000000000),
  "channel" text NOT NULL CHECK ("channel" = 'email'),
  "idempotency_key" text NOT NULL UNIQUE CHECK (
    length("idempotency_key") = 43
    AND "idempotency_key" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("idempotency_key", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  ),
  "payload_version" integer NOT NULL DEFAULT 1 CHECK ("payload_version" = 1),
  "template_version" integer NOT NULL DEFAULT 1 CHECK ("template_version" = 1),
  "payload_json" text NOT NULL CHECK (
    length("payload_json") BETWEEN 2 AND 4096
    AND json_valid("payload_json")
    AND json_type("payload_json") = 'object'
  ),
  -- The future Worker must verify this digest before delivery. SQL enforces the
  -- closed canonical payload shape and prevents snapshot/digest mutation.
  "payload_sha256" text NOT NULL CHECK (
    length("payload_sha256") = 64
    AND "payload_sha256" NOT GLOB '*[^a-f0-9]*'
  ),
  "rule_id" text NOT NULL CHECK (
    "rule_id" IN (
      'pgid.registration.rate_limited.v1',
      'pgid.registration.denied.v1',
      'pgid.registration.challenge_unavailable.v1',
      'pgid.registration.restricted_created.v1',
      'pgid.restricted.sensitive_denied.v1',
      'pgid.recovery.entry_abuse.v1',
      'pgid.recovery.passkey_failure.v1',
      'pgid.passkey.step_up_failure.v1',
      'pgid.oauth.client_report.v1',
      'pgid.admin.sensitive_activity.v1',
      'pgid.admin.directory_volume.v1',
      'pgid.security.fanout_gap.v1',
      'pgid.logout.delivery_health.v1',
      'pgid.alert.runtime_health.v1',
      'pgid.queue.dlq_approximate.v1'
    )
  ),
  "environment" text NOT NULL
    CHECK ("environment" IN ('local', 'preview', 'production')),
  "source_kind" text NOT NULL
    CHECK ("source_kind" IN ('d1_exact', 'queue_approximate')),
  "severity" text NOT NULL CHECK ("severity" IN ('warning', 'critical')),
  "incident_status" text NOT NULL
    CHECK ("incident_status" IN ('open', 'acknowledged', 'resolved')),
  "subject_ref" text CHECK (
    "subject_ref" IS NULL
    OR (
      length("subject_ref") = 43
      AND "subject_ref" NOT GLOB '*[^A-Za-z0-9_-]*'
      AND substr("subject_ref", -1) IN (
        'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
        'g', 'k', 'o', 's', 'w', '0', '4', '8'
      )
    )
  ),
  "hash_version" integer CHECK ("hash_version" IS NULL OR "hash_version" = 1),
  "provider" text CHECK (
    "provider" IS NULL
    OR "provider" IN (
      'google', 'discord', 'github', 'facebook', 'apple', 'telegram',
      'passkey', 'recovery'
    )
  ),
  "queue_name" text CHECK (
    "queue_name" IS NULL
    OR "queue_name" IN (
      'security_events', 'security_events_dlq',
      'logout_deliveries', 'logout_deliveries_dlq',
      'alert_deliveries', 'alert_deliveries_dlq',
      'audit_archive', 'audit_archive_dlq'
    )
  ),
  "reason" text CHECK (
    "reason" IS NULL
    OR "reason" IN (
      'rate_limited', 'denied', 'unavailable', 'invalid_state',
      'invalid_nonce', 'replay', 'timeout', 'backlog', 'dead_letter',
      'decrypt_failed', 'inconsistent', 'expired', 'rotation_failed',
      'delivery_failed', 'unknown'
    )
  ),
  "surface" text CHECK (
    "surface" IS NULL
    OR "surface" IN (
      'registration', 'login', 'oidc_authorize', 'oidc_token',
      'passkey', 'recovery', 'admin', 'audit', 'logout',
      'alert_delivery', 'archive'
    )
  ),
  "first_seen_at" date NOT NULL CHECK (
    typeof("first_seen_at") = 'text'
    AND length("first_seen_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "first_seen_at", '+0 seconds')
      IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "first_seen_at", '+0 seconds')
      = "first_seen_at"
  ),
  "last_seen_at" date NOT NULL CHECK (
    typeof("last_seen_at") = 'text'
    AND length("last_seen_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "last_seen_at", '+0 seconds')
      IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "last_seen_at", '+0 seconds')
      = "last_seen_at"
  ),
  "window_seconds" integer NOT NULL
    CHECK ("window_seconds" IN (300, 900, 3600)),
  "metric_name" text NOT NULL CHECK (
    "metric_name" IN (
      'count', 'ratio', 'rate_limited', 'high_risk_count', 'successes',
      'protected_denials', 'missing', 'dead',
      'oldest_unresolved_age_seconds', 'lease_expired', 'evaluator_missing',
      'evaluator_age_seconds', 'outbox_due_age_seconds', 'dead_outbox',
      'depth', 'consecutive_nonzero_samples'
    )
  ),
  "metric_kind" text NOT NULL CHECK (
    "metric_kind" IN ('count', 'ratio', 'age_seconds', 'consecutive', 'boolean')
  ),
  "metric_unit" text NOT NULL CHECK (
    "metric_unit" IN ('events', 'basis_points', 'seconds', 'samples', 'state')
  ),
  "observed_value" integer NOT NULL
    CHECK ("observed_value" BETWEEN 0 AND 1000000000),
  "observed_numerator" integer CHECK (
    "observed_numerator" IS NULL
    OR "observed_numerator" BETWEEN 0 AND 1000000
  ),
  "observed_denominator" integer CHECK (
    "observed_denominator" IS NULL
    OR "observed_denominator" BETWEEN 1 AND 1000000
  ),
  "minimum_sample_count" integer NOT NULL DEFAULT 0
    CHECK ("minimum_sample_count" BETWEEN 0 AND 1000000),
  "minimum_numerator_count" integer CHECK (
    "minimum_numerator_count" IS NULL
    OR "minimum_numerator_count" BETWEEN 1 AND 1000000
  ),
  "threshold" integer NOT NULL CHECK ("threshold" BETWEEN 1 AND 1000000000),
  "secondary_metric_name" text CHECK (
    "secondary_metric_name" IS NULL
    OR "secondary_metric_name" IN ('known_surfaces', 'distinct_reporters')
  ),
  "secondary_metric_kind" text CHECK (
    "secondary_metric_kind" IS NULL OR "secondary_metric_kind" = 'count'
  ),
  "secondary_metric_unit" text CHECK (
    "secondary_metric_unit" IS NULL OR "secondary_metric_unit" = 'events'
  ),
  "secondary_observed_value" integer CHECK (
    "secondary_observed_value" IS NULL
    OR "secondary_observed_value" BETWEEN 0 AND 1000000000
  ),
  "secondary_threshold" integer CHECK (
    "secondary_threshold" IS NULL
    OR "secondary_threshold" BETWEEN 1 AND 1000000000
  ),
  "status" text NOT NULL
    CHECK ("status" IN ('pending', 'processing', 'retry', 'accepted', 'dead')),
  "attempts" integer NOT NULL DEFAULT 0 CHECK ("attempts" BETWEEN 0 AND 5),
  "replay_count" integer NOT NULL DEFAULT 0
    CHECK ("replay_count" BETWEEN 0 AND 1000),
  "next_attempt_at" date CHECK (
    "next_attempt_at" IS NULL
    OR (typeof("next_attempt_at") = 'text'
      AND length("next_attempt_at") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "next_attempt_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "next_attempt_at", '+0 seconds'
      )
        = "next_attempt_at")
  ),
  "lease_id" text CHECK (
    "lease_id" IS NULL OR length("lease_id") = 36
  ),
  "lease_expires_at" date CHECK (
    "lease_expires_at" IS NULL
    OR (typeof("lease_expires_at") = 'text'
      AND length("lease_expires_at") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "lease_expires_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "lease_expires_at", '+0 seconds'
      )
        = "lease_expires_at")
  ),
  "accepted_at" date CHECK (
    "accepted_at" IS NULL
    OR (typeof("accepted_at") = 'text'
      AND length("accepted_at") = 24
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "accepted_at", '+0 seconds')
        IS NOT NULL
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "accepted_at", '+0 seconds')
        = "accepted_at")
  ),
  "dead_at" date CHECK (
    "dead_at" IS NULL
    OR (typeof("dead_at") = 'text'
      AND length("dead_at") = 24
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "dead_at", '+0 seconds')
        IS NOT NULL
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "dead_at", '+0 seconds')
        = "dead_at")
  ),
  "last_error_code" text CHECK (
    "last_error_code" IS NULL
    OR "last_error_code" IN (
      'network', 'timeout', 'email_rate_limit', 'email_daily_limit',
      'email_internal', 'email_delivery', 'email_validation',
      'email_authentication', 'email_recipient', 'email_sender',
      'email_content', 'lease_expired', 'email_unknown_transient',
      'payload_integrity'
    )
  ),
  "created_at" date NOT NULL CHECK (
    typeof("created_at") = 'text'
    AND length("created_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds') IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds')
      = "created_at"
  ),
  "updated_at" date NOT NULL CHECK (
    typeof("updated_at") = 'text'
    AND length("updated_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "updated_at", '+0 seconds') IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "updated_at", '+0 seconds')
      = "updated_at"
  ),
  UNIQUE (
    "alert_id", "generation", "event_kind", "event_sequence", "channel"
  ),
  FOREIGN KEY (
    "alert_id", "generation", "rule_id", "environment", "source_kind"
  ) REFERENCES "security_alert" (
    "id", "generation", "rule_id", "environment", "source_kind"
  ) ON DELETE RESTRICT,
  CHECK (
    typeof("id") = 'integer'
    AND typeof("generation") = 'integer'
    AND typeof("event_sequence") = 'integer'
    AND typeof("payload_version") = 'integer'
    AND typeof("template_version") = 'integer'
    AND ("hash_version" IS NULL OR typeof("hash_version") = 'integer')
    AND typeof("window_seconds") = 'integer'
    AND typeof("observed_value") = 'integer'
    AND ("observed_numerator" IS NULL
      OR typeof("observed_numerator") = 'integer')
    AND ("observed_denominator" IS NULL
      OR typeof("observed_denominator") = 'integer')
    AND typeof("minimum_sample_count") = 'integer'
    AND ("minimum_numerator_count" IS NULL
      OR typeof("minimum_numerator_count") = 'integer')
    AND typeof("threshold") = 'integer'
    AND ("secondary_observed_value" IS NULL
      OR typeof("secondary_observed_value") = 'integer')
    AND ("secondary_threshold" IS NULL
      OR typeof("secondary_threshold") = 'integer')
    AND typeof("attempts") = 'integer'
    AND typeof("replay_count") = 'integer'
  ),
  CHECK (
    "payload_json" = json_object(
      'schemaVersion', "payload_version",
      'templateVersion', "template_version",
      'incidentId', "alert_id",
      'generation', "generation",
      'deliveryId', "delivery_key",
      'idempotencyKey', "idempotency_key",
      'eventKind', "event_kind",
      'eventSequence', "event_sequence",
      'channel', "channel",
      'rule', "rule_id",
      'environment', "environment",
      'sourceKind', "source_kind",
      'severity', "severity",
      'status', "incident_status",
      'firstSeenAt', "first_seen_at",
      'lastSeenAt', "last_seen_at",
      'windowSeconds', "window_seconds",
      'metricName', "metric_name",
      'metricKind', "metric_kind",
      'metricUnit', "metric_unit",
      'observedValue', "observed_value",
      'observedNumerator', "observed_numerator",
      'observedDenominator', "observed_denominator",
      'minimumSampleCount', "minimum_sample_count",
      'minimumNumeratorCount', "minimum_numerator_count",
      'threshold', "threshold",
      'secondaryMetricName', "secondary_metric_name",
      'secondaryMetricKind', "secondary_metric_kind",
      'secondaryMetricUnit', "secondary_metric_unit",
      'secondaryObservedValue', "secondary_observed_value",
      'secondaryThreshold', "secondary_threshold",
      'subjectRef', "subject_ref",
      'hashVersion', "hash_version",
      'provider', "provider",
      'queue', "queue_name",
      'reason', "reason",
      'surface', "surface"
    )
  ),
  CHECK (
    ("subject_ref" IS NULL AND "hash_version" IS NULL)
    OR ("subject_ref" IS NOT NULL AND "hash_version" IS 1)
  ),
  CHECK ("provider" IS NULL AND "reason" IS NULL AND "surface" IS NULL),
  CHECK (
    ("rule_id" = 'pgid.queue.dlq_approximate.v1'
      AND "source_kind" = 'queue_approximate')
    OR ("rule_id" <> 'pgid.queue.dlq_approximate.v1'
      AND "source_kind" = 'd1_exact')
  ),
  CHECK (
    ("event_kind" = 'opened' AND "incident_status" = 'open')
    OR ("event_kind" = 'resolved' AND "incident_status" = 'resolved')
    OR ("event_kind" IN ('reminder', 'escalated')
      AND "incident_status" IN ('open', 'acknowledged'))
  ),
  CHECK ("event_kind" <> 'escalated' OR "severity" = 'critical'),
  CHECK ("event_kind" = 'reminder' OR "event_sequence" = 1),
  CHECK (
    ("metric_name" = 'ratio'
      AND "metric_kind" = 'ratio'
      AND "metric_unit" = 'basis_points')
    OR ("metric_name" IN (
        'oldest_unresolved_age_seconds', 'evaluator_age_seconds',
        'outbox_due_age_seconds'
      )
      AND "metric_kind" = 'age_seconds'
      AND "metric_unit" = 'seconds')
    OR ("metric_name" = 'evaluator_missing'
      AND "metric_kind" = 'boolean'
      AND "metric_unit" = 'state')
    OR ("metric_name" = 'consecutive_nonzero_samples'
      AND "metric_kind" = 'consecutive'
      AND "metric_unit" = 'samples')
    OR ("metric_name" IN (
        'count', 'rate_limited', 'high_risk_count', 'successes',
        'protected_denials', 'missing', 'dead', 'lease_expired',
        'dead_outbox', 'depth'
      )
      AND "metric_kind" = 'count'
      AND "metric_unit" = 'events')
  ),
  CHECK (
    ("rule_id" = 'pgid.registration.rate_limited.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.registration.denied.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.registration.challenge_unavailable.v1'
      AND "metric_name" = 'ratio')
    OR ("rule_id" = 'pgid.registration.restricted_created.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.restricted.sensitive_denied.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.recovery.entry_abuse.v1'
      AND "metric_name" IN ('rate_limited', 'ratio'))
    OR ("rule_id" = 'pgid.recovery.passkey_failure.v1'
      AND "metric_name" = 'ratio')
    OR ("rule_id" = 'pgid.passkey.step_up_failure.v1'
      AND "metric_name" = 'ratio')
    OR ("rule_id" = 'pgid.oauth.client_report.v1'
      AND "metric_name" IN ('count', 'high_risk_count'))
    OR ("rule_id" = 'pgid.admin.sensitive_activity.v1'
      AND "metric_name" IN ('count', 'successes', 'protected_denials'))
    OR ("rule_id" = 'pgid.admin.directory_volume.v1'
      AND "metric_name" = 'count')
    OR ("rule_id" = 'pgid.logout.delivery_health.v1'
      AND "metric_name" IN (
        'dead', 'oldest_unresolved_age_seconds', 'lease_expired', 'ratio'
      ))
    OR ("rule_id" = 'pgid.alert.runtime_health.v1'
      AND "metric_name" IN (
        'evaluator_missing', 'evaluator_age_seconds',
        'outbox_due_age_seconds', 'dead_outbox'
      ))
    OR ("rule_id" = 'pgid.security.fanout_gap.v1'
      AND "metric_name" = 'missing')
    OR ("rule_id" = 'pgid.queue.dlq_approximate.v1'
      AND "metric_name" IN ('depth', 'consecutive_nonzero_samples'))
  ),
  CHECK (
    ("metric_kind" = 'count'
      AND "metric_unit" = 'events'
      AND "observed_numerator" IS NULL
      AND "observed_denominator" IS NULL
      AND "minimum_sample_count" = 0
      AND "minimum_numerator_count" IS NULL)
    OR ("metric_kind" = 'ratio'
      AND "metric_unit" = 'basis_points'
      AND "observed_numerator" IS NOT NULL
      AND "observed_denominator" IS NOT NULL
      AND "minimum_numerator_count" IS NOT NULL
      AND "minimum_numerator_count" <= "observed_numerator"
      AND "minimum_numerator_count" <= "observed_denominator"
      AND "observed_numerator" <= "observed_denominator"
      AND "observed_denominator" >= "minimum_sample_count"
      AND "observed_value" =
        ("observed_numerator" * 10000) / "observed_denominator")
    OR ("metric_kind" = 'age_seconds'
      AND "metric_unit" = 'seconds'
      AND "observed_numerator" IS NULL
      AND "observed_denominator" IS NULL
      AND "minimum_sample_count" = 0
      AND "minimum_numerator_count" IS NULL)
    OR ("metric_kind" = 'consecutive'
      AND "metric_unit" = 'samples'
      AND "observed_numerator" IS NULL
      AND "observed_denominator" IS NULL
      AND "minimum_sample_count" = 0
      AND "minimum_numerator_count" IS NULL)
    OR ("metric_kind" = 'boolean'
      AND "metric_unit" = 'state'
      AND "observed_value" IN (0, 1)
      AND "observed_numerator" IS NULL
      AND "observed_denominator" IS NULL
      AND "minimum_sample_count" = 0
      AND "minimum_numerator_count" IS NULL)
  ),
  CHECK (
    ("secondary_metric_name" IS NULL
      AND "secondary_metric_kind" IS NULL
      AND "secondary_metric_unit" IS NULL
      AND "secondary_observed_value" IS NULL
      AND "secondary_threshold" IS NULL)
    OR ("secondary_metric_name" IS NOT NULL
      AND "secondary_metric_kind" = 'count'
      AND "secondary_metric_unit" = 'events'
      AND "secondary_observed_value" IS NOT NULL
      AND "secondary_threshold" IS NOT NULL)
  ),
  CHECK (
    "secondary_metric_name" IS NULL
    OR ("rule_id" = 'pgid.restricted.sensitive_denied.v1'
      AND "metric_name" = 'count'
      AND "secondary_metric_name" = 'known_surfaces')
    OR ("rule_id" = 'pgid.oauth.client_report.v1'
      AND "metric_name" = 'high_risk_count'
      AND "secondary_metric_name" = 'distinct_reporters')
  ),
  CHECK (
    "secondary_metric_name" IS NOT 'known_surfaces'
    OR ("secondary_observed_value" <= "observed_value"
      AND "secondary_observed_value" <= 7)
  ),
  CHECK ("observed_value" >= "threshold"),
  CHECK (
    "secondary_metric_name" IS NULL
    OR "secondary_observed_value" >= "secondary_threshold"
  ),
  CHECK ("last_seen_at" >= "first_seen_at"),
  CHECK ("updated_at" >= "created_at"),
  CHECK (
    ("lease_id" IS NULL AND "lease_expires_at" IS NULL)
    OR ("lease_id" IS NOT NULL AND "lease_expires_at" IS NOT NULL)
  ),
  CHECK (
    ("status" = 'processing'
      AND "lease_id" IS NOT NULL
      AND "lease_expires_at" IS NOT NULL)
    OR ("status" <> 'processing'
      AND "lease_id" IS NULL
      AND "lease_expires_at" IS NULL)
  ),
  CHECK (
    ("status" IN ('pending', 'retry') AND "next_attempt_at" IS NOT NULL)
    OR ("status" NOT IN ('pending', 'retry') AND "next_attempt_at" IS NULL)
  ),
  CHECK (
    ("status" = 'accepted' AND "accepted_at" IS NOT NULL)
    OR ("status" <> 'accepted' AND "accepted_at" IS NULL)
  ),
  CHECK (
    ("status" = 'dead' AND "dead_at" IS NOT NULL)
    OR ("status" <> 'dead' AND "dead_at" IS NULL)
  ),
  CHECK (
    ("status" IN ('retry', 'dead') AND "last_error_code" IS NOT NULL)
    OR ("status" NOT IN ('retry', 'dead') AND "last_error_code" IS NULL)
  ),
  CHECK (
    "last_error_code" IS NOT 'payload_integrity'
    OR "status" = 'dead'
  ),
  CHECK (
    ("status" = 'pending' AND "attempts" = 0)
    OR ("status" = 'processing' AND "attempts" BETWEEN 1 AND 5)
    OR ("status" = 'retry' AND "attempts" BETWEEN 1 AND 4)
    OR ("status" IN ('accepted', 'dead') AND "attempts" BETWEEN 1 AND 5)
  )
);

-- D1 serializes writes, so this trigger and the unique event tuple make the
-- next reminder sequence a single atomic decision for each incident generation.
CREATE TRIGGER "alert_outbox_reminder_sequence_guard"
BEFORE INSERT ON "alert_outbox"
WHEN NEW."event_kind" = 'reminder'
  AND NEW."event_sequence" <> coalesce((
    SELECT max(existing."event_sequence") + 1
      FROM "alert_outbox" AS existing
     WHERE existing."alert_id" = NEW."alert_id"
       AND existing."generation" = NEW."generation"
       AND existing."event_kind" = 'reminder'
       AND existing."channel" = NEW."channel"
  ), 1)
BEGIN
  SELECT RAISE(ABORT, 'alert reminder sequence must be contiguous');
END;

CREATE TRIGGER "alert_outbox_snapshot_immutable"
BEFORE UPDATE ON "alert_outbox"
WHEN NEW."delivery_key" <> OLD."delivery_key"
  OR NEW."alert_id" <> OLD."alert_id"
  OR NEW."generation" <> OLD."generation"
  OR NEW."event_kind" <> OLD."event_kind"
  OR NEW."event_sequence" <> OLD."event_sequence"
  OR NEW."channel" <> OLD."channel"
  OR NEW."idempotency_key" <> OLD."idempotency_key"
  OR NEW."payload_version" <> OLD."payload_version"
  OR NEW."template_version" <> OLD."template_version"
  OR NEW."payload_json" <> OLD."payload_json"
  OR NEW."payload_sha256" <> OLD."payload_sha256"
  OR NEW."rule_id" <> OLD."rule_id"
  OR NEW."environment" <> OLD."environment"
  OR NEW."source_kind" <> OLD."source_kind"
  OR NEW."severity" <> OLD."severity"
  OR NEW."incident_status" <> OLD."incident_status"
  OR NEW."subject_ref" IS NOT OLD."subject_ref"
  OR NEW."hash_version" IS NOT OLD."hash_version"
  OR NEW."provider" IS NOT OLD."provider"
  OR NEW."queue_name" IS NOT OLD."queue_name"
  OR NEW."reason" IS NOT OLD."reason"
  OR NEW."surface" IS NOT OLD."surface"
  OR NEW."first_seen_at" <> OLD."first_seen_at"
  OR NEW."last_seen_at" <> OLD."last_seen_at"
  OR NEW."window_seconds" <> OLD."window_seconds"
  OR NEW."metric_name" <> OLD."metric_name"
  OR NEW."metric_kind" <> OLD."metric_kind"
  OR NEW."metric_unit" <> OLD."metric_unit"
  OR NEW."observed_value" <> OLD."observed_value"
  OR NEW."observed_numerator" IS NOT OLD."observed_numerator"
  OR NEW."observed_denominator" IS NOT OLD."observed_denominator"
  OR NEW."minimum_sample_count" <> OLD."minimum_sample_count"
  OR NEW."minimum_numerator_count" IS NOT OLD."minimum_numerator_count"
  OR NEW."threshold" <> OLD."threshold"
  OR NEW."secondary_metric_name" IS NOT OLD."secondary_metric_name"
  OR NEW."secondary_metric_kind" IS NOT OLD."secondary_metric_kind"
  OR NEW."secondary_metric_unit" IS NOT OLD."secondary_metric_unit"
  OR NEW."secondary_observed_value" IS NOT OLD."secondary_observed_value"
  OR NEW."secondary_threshold" IS NOT OLD."secondary_threshold"
  OR NEW."created_at" <> OLD."created_at"
BEGIN
  SELECT RAISE(ABORT, 'alert delivery snapshot is immutable');
END;

CREATE TRIGGER "alert_outbox_incident_snapshot_guard"
BEFORE INSERT ON "alert_outbox"
WHEN NEW."status" <> 'pending'
  OR NEW."attempts" <> 0
  OR NEW."replay_count" <> 0
  OR NEW."next_attempt_at" IS NULL
  OR NEW."lease_id" IS NOT NULL
  OR NEW."lease_expires_at" IS NOT NULL
  OR NEW."accepted_at" IS NOT NULL
  OR NEW."dead_at" IS NOT NULL
  OR NEW."last_error_code" IS NOT NULL
  OR NEW."next_attempt_at" < NEW."created_at"
  OR NOT EXISTS (
  SELECT 1
    FROM "security_alert" AS a
    JOIN "alert_state" AS s ON s."id" = a."state_id"
   WHERE a."id" = NEW."alert_id"
     AND a."generation" = NEW."generation"
     AND a."rule_id" = NEW."rule_id"
     AND a."environment" = NEW."environment"
     AND a."source_kind" = NEW."source_kind"
     AND a."severity" = NEW."severity"
     AND a."status" = NEW."incident_status"
     AND a."first_seen_at" = NEW."first_seen_at"
     AND a."last_seen_at" = NEW."last_seen_at"
     AND a."window_seconds" = NEW."window_seconds"
     AND a."metric_name" = NEW."metric_name"
     AND a."metric_kind" = NEW."metric_kind"
     AND a."metric_unit" = NEW."metric_unit"
     AND a."observed_value" = NEW."observed_value"
     AND a."observed_numerator" IS NEW."observed_numerator"
     AND a."observed_denominator" IS NEW."observed_denominator"
     AND a."minimum_sample_count" = NEW."minimum_sample_count"
     AND a."minimum_numerator_count" IS NEW."minimum_numerator_count"
     AND a."threshold" = NEW."threshold"
     AND a."secondary_metric_name" IS NEW."secondary_metric_name"
     AND a."secondary_metric_kind" IS NEW."secondary_metric_kind"
     AND a."secondary_metric_unit" IS NEW."secondary_metric_unit"
     AND a."secondary_observed_value" IS NEW."secondary_observed_value"
     AND a."secondary_threshold" IS NEW."secondary_threshold"
     AND s."generation" = NEW."generation"
     AND (
       (NEW."event_kind" = 'resolved' AND s."current_severity" = 'none')
       OR (NEW."event_kind" <> 'resolved'
         AND s."current_severity" = NEW."severity")
     )
     AND s."subject_ref" IS NEW."subject_ref"
     AND s."hash_version" IS NEW."hash_version"
     AND s."provider" IS NEW."provider"
     AND s."queue_name" IS NEW."queue_name"
     AND s."reason" IS NEW."reason"
     AND s."surface" IS NEW."surface"
)
BEGIN
  SELECT RAISE(ABORT, 'alert delivery snapshot does not match its incident');
END;

-- The delivery state machine is closed even before Worker code exists. Claims
-- are the only attempt increment, processing is the only path to a result, and
-- a new replay generation may start only from a terminal row. This does not
-- authorize replay; the future admin Worker still owns actor/session guards.
CREATE TRIGGER "alert_outbox_transition_guard"
BEFORE UPDATE ON "alert_outbox"
WHEN NEW."updated_at" < OLD."updated_at"
  OR NOT (
  (NEW."replay_count" = OLD."replay_count"
    AND NEW."status" = OLD."status"
    AND NEW."attempts" = OLD."attempts"
    AND NEW."next_attempt_at" IS OLD."next_attempt_at"
    AND NEW."lease_id" IS OLD."lease_id"
    AND NEW."lease_expires_at" IS OLD."lease_expires_at"
    AND NEW."accepted_at" IS OLD."accepted_at"
    AND NEW."dead_at" IS OLD."dead_at"
    AND NEW."last_error_code" IS OLD."last_error_code")
  OR (NEW."replay_count" = OLD."replay_count"
    AND OLD."status" IN ('pending', 'retry')
    AND NEW."status" = 'processing'
    AND NEW."attempts" = OLD."attempts" + 1
    AND NEW."updated_at" >= OLD."next_attempt_at"
    AND NEW."lease_expires_at" > NEW."updated_at")
  OR (NEW."replay_count" = OLD."replay_count"
    AND OLD."status" = 'processing'
    AND NEW."status" IN ('accepted', 'retry', 'dead')
    AND NEW."attempts" = OLD."attempts"
    AND (
      (NEW."status" = 'accepted' AND NEW."accepted_at" = NEW."updated_at")
      OR (NEW."status" = 'dead' AND NEW."dead_at" = NEW."updated_at")
      OR (NEW."status" = 'retry'
        AND NEW."next_attempt_at" > NEW."updated_at")
    )
    AND EXISTS (
      SELECT 1
        FROM "alert_delivery_attempt" AS attempt
       WHERE attempt."outbox_id" = OLD."id"
         AND attempt."replay_count" = OLD."replay_count"
         AND attempt."attempt_number" = OLD."attempts"
         AND attempt."lease_id" = OLD."lease_id"
         AND attempt."outcome" <> 'in_flight'
         AND attempt."resulting_status" = NEW."status"
         AND attempt."error_code" IS NEW."last_error_code"
         AND NEW."updated_at" >= attempt."completed_at"
    ))
  OR (NEW."replay_count" = OLD."replay_count" + 1
    AND OLD."status" IN ('accepted', 'dead')
    AND OLD."last_error_code" IS NOT 'payload_integrity'
    AND NEW."status" = 'pending'
    AND NEW."attempts" = 0
    AND NEW."next_attempt_at" >= NEW."updated_at")
)
BEGIN
  SELECT RAISE(ABORT, 'invalid alert delivery transition');
END;

CREATE INDEX "alert_outbox_due_idx"
  ON "alert_outbox" ("status", "next_attempt_at", "lease_expires_at");

CREATE INDEX "alert_outbox_operator_idx"
  ON "alert_outbox" ("status", "updated_at" DESC);

CREATE TABLE "alert_delivery_attempt" (
  "id" text PRIMARY KEY NOT NULL CHECK (length("id") = 36),
  "outbox_id" integer NOT NULL
    REFERENCES "alert_outbox" ("id") ON DELETE CASCADE,
  "replay_count" integer NOT NULL
    CHECK ("replay_count" BETWEEN 0 AND 1000),
  "attempt_number" integer NOT NULL CHECK ("attempt_number" BETWEEN 1 AND 5),
  "lease_id" text NOT NULL UNIQUE CHECK (length("lease_id") = 36),
  "outcome" text NOT NULL CHECK (
    "outcome" IN ('in_flight', 'accepted', 'retry', 'dead', 'lease_expired')
  ),
  "resulting_status" text NOT NULL CHECK (
    "resulting_status" IN ('processing', 'accepted', 'retry', 'dead')
  ),
  "error_code" text CHECK (
    "error_code" IS NULL
    OR "error_code" IN (
      'network', 'timeout', 'email_rate_limit', 'email_daily_limit',
      'email_internal', 'email_delivery', 'email_validation',
      'email_authentication', 'email_recipient', 'email_sender',
      'email_content', 'lease_expired', 'email_unknown_transient',
      'payload_integrity'
    )
  ),
  "started_at" date NOT NULL CHECK (
    typeof("started_at") = 'text'
    AND length("started_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "started_at", '+0 seconds')
      IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "started_at", '+0 seconds')
      = "started_at"
  ),
  "completed_at" date CHECK (
    "completed_at" IS NULL
    OR (typeof("completed_at") = 'text'
      AND length("completed_at") = 24
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "completed_at", '+0 seconds')
        IS NOT NULL
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "completed_at", '+0 seconds')
        = "completed_at")
  ),
  UNIQUE ("outbox_id", "replay_count", "attempt_number"),
  CHECK (
    typeof("outbox_id") = 'integer'
    AND typeof("replay_count") = 'integer'
    AND typeof("attempt_number") = 'integer'
  ),
  CHECK (
    "completed_at" IS NULL
    OR "completed_at" >= "started_at"
  ),
  CHECK (
    ("outcome" = 'in_flight'
      AND "resulting_status" = 'processing'
      AND "error_code" IS NULL
      AND "completed_at" IS NULL)
    OR ("outcome" <> 'in_flight'
      AND "resulting_status" IN ('accepted', 'retry', 'dead')
      AND "completed_at" IS NOT NULL)
  ),
  CHECK (
    "outcome" <> 'accepted'
    OR (
      "resulting_status" = 'accepted'
      AND "error_code" IS NULL
    )
  ),
  CHECK ("outcome" <> 'retry' OR "resulting_status" = 'retry'),
  CHECK ("outcome" <> 'dead' OR "resulting_status" = 'dead'),
  CHECK (
    "outcome" <> 'lease_expired'
    OR (
      "resulting_status" IN ('retry', 'dead')
      AND "error_code" = 'lease_expired'
    )
  ),
  CHECK (
    "outcome" IN ('in_flight', 'accepted', 'lease_expired')
    OR "error_code" IS NOT NULL
  ),
  CHECK (
    "error_code" IS NOT 'payload_integrity'
    OR ("outcome" = 'dead' AND "resulting_status" = 'dead')
  )
);

-- A claim is persisted on the outbox first, then its in-flight attempt is
-- inserted in the same D1 batch. No attempt may be invented for a stale replay,
-- attempt number, or lease.
CREATE TRIGGER "alert_delivery_attempt_insert_guard"
BEFORE INSERT ON "alert_delivery_attempt"
WHEN NEW."outcome" <> 'in_flight'
  OR NOT EXISTS (
    SELECT 1
      FROM "alert_outbox" AS delivery
     WHERE delivery."id" = NEW."outbox_id"
       AND delivery."status" = 'processing'
       AND delivery."replay_count" = NEW."replay_count"
       AND delivery."attempts" = NEW."attempt_number"
       AND delivery."lease_id" = NEW."lease_id"
       AND NEW."started_at" >= delivery."updated_at"
       AND NEW."started_at" < delivery."lease_expires_at"
  )
BEGIN
  SELECT RAISE(ABORT, 'alert attempt does not match its active delivery claim');
END;

-- Provider I/O completes the in-flight attempt while its exact lease is still
-- active. The following outbox update, in the same batch, consumes this terminal
-- evidence. A completed attempt is immutable.
CREATE TRIGGER "alert_delivery_attempt_transition_guard"
BEFORE UPDATE ON "alert_delivery_attempt"
WHEN OLD."outcome" <> 'in_flight'
  OR NEW."id" <> OLD."id"
  OR NEW."outbox_id" <> OLD."outbox_id"
  OR NEW."replay_count" <> OLD."replay_count"
  OR NEW."attempt_number" <> OLD."attempt_number"
  OR NEW."lease_id" <> OLD."lease_id"
  OR NEW."started_at" <> OLD."started_at"
  OR NEW."outcome" NOT IN ('accepted', 'retry', 'dead', 'lease_expired')
  OR NOT EXISTS (
    SELECT 1
      FROM "alert_outbox" AS delivery
     WHERE delivery."id" = OLD."outbox_id"
       AND delivery."status" = 'processing'
       AND delivery."replay_count" = OLD."replay_count"
       AND delivery."attempts" = OLD."attempt_number"
       AND delivery."lease_id" = OLD."lease_id"
       AND (
         (NEW."outcome" = 'lease_expired'
           AND NEW."completed_at" >= delivery."lease_expires_at")
         OR (NEW."outcome" IN ('accepted', 'retry', 'dead')
           AND NEW."completed_at" < delivery."lease_expires_at")
       )
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid alert delivery attempt transition');
END;

CREATE INDEX "alert_delivery_attempt_time_idx"
  ON "alert_delivery_attempt" ("started_at" DESC);

-- This table constrains persisted chronology and ownership, but cannot prove
-- that evaluator work ran. Only the future evaluator repository may publish
-- healthy + last_success_at in its controlled successful-run transaction;
-- consumers must not treat an inserted status string as execution proof.
CREATE TABLE "alert_runtime_status" (
  "component" text PRIMARY KEY NOT NULL CHECK (
    "component" IN (
      'evaluator', 'delivery', 'security_queue', 'security_dlq',
      'logout_queue', 'logout_dlq', 'alert_queue', 'alert_dlq',
      'audit_archive_queue', 'audit_archive_dlq', 'audit_fanout'
    )
  ),
  "status" text NOT NULL DEFAULT 'disabled'
    CHECK ("status" IN ('disabled', 'healthy', 'degraded', 'failing', 'unavailable')),
  "generation" integer NOT NULL DEFAULT 0
    CHECK ("generation" BETWEEN 0 AND 1000000),
  "revision" integer NOT NULL DEFAULT 0
    CHECK ("revision" BETWEEN 0 AND 1000000000),
  "lease_id" text CHECK ("lease_id" IS NULL OR length("lease_id") = 36),
  "lease_expires_at" date CHECK (
    "lease_expires_at" IS NULL
    OR (typeof("lease_expires_at") = 'text'
      AND length("lease_expires_at") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "lease_expires_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "lease_expires_at", '+0 seconds'
      )
        = "lease_expires_at")
  ),
  "last_started_at" date CHECK (
    "last_started_at" IS NULL
    OR (typeof("last_started_at") = 'text'
      AND length("last_started_at") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_started_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_started_at", '+0 seconds'
      )
        = "last_started_at")
  ),
  "last_success_at" date CHECK (
    "last_success_at" IS NULL
    OR (typeof("last_success_at") = 'text'
      AND length("last_success_at") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_success_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_success_at", '+0 seconds'
      )
        = "last_success_at")
  ),
  "last_error_at" date CHECK (
    "last_error_at" IS NULL
    OR (typeof("last_error_at") = 'text'
      AND length("last_error_at") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_error_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_error_at", '+0 seconds'
      )
        = "last_error_at")
  ),
  "last_error_code" text CHECK (
    "last_error_code" IS NULL
    OR "last_error_code" IN (
      'metrics_unavailable', 'evaluator_failed', 'delivery_failed',
      'fanout_failed', 'logout_failed', 'source_incomplete', 'unknown'
    )
  ),
  "metric_sampled_at" date CHECK (
    "metric_sampled_at" IS NULL
    OR (typeof("metric_sampled_at") = 'text'
      AND length("metric_sampled_at") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "metric_sampled_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "metric_sampled_at", '+0 seconds'
      )
        = "metric_sampled_at")
  ),
  "backlog_count" integer
    CHECK ("backlog_count" IS NULL OR "backlog_count" BETWEEN 0 AND 1000000000),
  "backlog_bytes" integer CHECK (
    "backlog_bytes" IS NULL OR "backlog_bytes" BETWEEN 0 AND 1000000000000
  ),
  "oldest_message_age_seconds" integer CHECK (
    "oldest_message_age_seconds" IS NULL
    OR "oldest_message_age_seconds" BETWEEN 0 AND 1000000000
  ),
  "nonzero_since_at" date CHECK (
    "nonzero_since_at" IS NULL
    OR (typeof("nonzero_since_at") = 'text'
      AND length("nonzero_since_at") = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "nonzero_since_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "nonzero_since_at", '+0 seconds'
      )
        = "nonzero_since_at")
  ),
  "consecutive_nonzero_samples" integer CHECK (
    "consecutive_nonzero_samples" IS NULL
    OR "consecutive_nonzero_samples" BETWEEN 0 AND 1000000
  ),
  "watermark_at" date CHECK (
    "watermark_at" IS NULL
    OR (typeof("watermark_at") = 'text'
      AND length("watermark_at") = 24
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "watermark_at", '+0 seconds')
        IS NOT NULL
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "watermark_at", '+0 seconds')
        = "watermark_at")
  ),
  "updated_at" date NOT NULL CHECK (
    typeof("updated_at") = 'text'
    AND length("updated_at") = 24
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "updated_at", '+0 seconds') IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "updated_at", '+0 seconds')
      = "updated_at"
  ),
  CHECK (
    typeof("generation") = 'integer'
    AND typeof("revision") = 'integer'
    AND ("backlog_count" IS NULL OR typeof("backlog_count") = 'integer')
    AND ("backlog_bytes" IS NULL OR typeof("backlog_bytes") = 'integer')
    AND ("oldest_message_age_seconds" IS NULL
      OR typeof("oldest_message_age_seconds") = 'integer')
    AND ("consecutive_nonzero_samples" IS NULL
      OR typeof("consecutive_nonzero_samples") = 'integer')
  ),
  CHECK (
    ("lease_id" IS NULL AND "lease_expires_at" IS NULL)
    OR ("lease_id" IS NOT NULL AND "lease_expires_at" IS NOT NULL)
  ),
  CHECK (
    "lease_id" IS NULL
    OR ("lease_expires_at" > "updated_at"
      AND "lease_expires_at" <= strftime(
        '%Y-%m-%dT%H:%M:%fZ', "updated_at", '+300 seconds'
      ))
  ),
  CHECK (
    ("last_error_at" IS NULL AND "last_error_code" IS NULL)
    OR ("last_error_at" IS NOT NULL AND "last_error_code" IS NOT NULL)
  ),
  CHECK (
    ("metric_sampled_at" IS NULL
      AND "backlog_count" IS NULL
      AND "backlog_bytes" IS NULL
      AND "oldest_message_age_seconds" IS NULL
      AND "nonzero_since_at" IS NULL
      AND "consecutive_nonzero_samples" IS NULL)
    OR ("metric_sampled_at" IS NOT NULL
      AND "component" IN (
        'security_queue', 'security_dlq', 'logout_queue', 'logout_dlq',
        'alert_queue', 'alert_dlq', 'audit_archive_queue', 'audit_archive_dlq'
      )
      AND "backlog_count" IS NOT NULL
      AND "backlog_bytes" IS NOT NULL
      AND "oldest_message_age_seconds" IS NOT NULL
      AND (
        ("backlog_count" = 0
          AND "nonzero_since_at" IS NULL
          AND "consecutive_nonzero_samples" = 0)
        OR ("backlog_count" > 0
          AND "nonzero_since_at" IS NOT NULL
          AND "nonzero_since_at" <= "metric_sampled_at"
          AND "consecutive_nonzero_samples" BETWEEN 1 AND 1000000)
      ))
  ),
  CHECK (
    "metric_sampled_at" IS NULL
    OR "metric_sampled_at" <= "updated_at"
  ),
  CHECK (
    "last_started_at" IS NULL
    OR "last_started_at" <= "updated_at"
  ),
  CHECK (
    "last_success_at" IS NULL
    OR "last_success_at" <= "updated_at"
  ),
  CHECK (
    "last_error_at" IS NULL
    OR "last_error_at" <= "updated_at"
  ),
  CHECK (
    "watermark_at" IS NULL
    OR ("last_success_at" IS NOT NULL
      AND "watermark_at" <= "last_success_at")
  )
);

CREATE TRIGGER "alert_runtime_status_initial_guard"
BEFORE INSERT ON "alert_runtime_status"
WHEN NEW."generation" <> 0
  OR NEW."revision" <> 0
  OR NEW."lease_id" IS NOT NULL
  OR NEW."lease_expires_at" IS NOT NULL
  OR (NEW."component" = 'evaluator' AND (
    NEW."status" <> 'disabled'
    OR NEW."last_started_at" IS NOT NULL
    OR NEW."last_success_at" IS NOT NULL
    OR NEW."last_error_at" IS NOT NULL
    OR NEW."last_error_code" IS NOT NULL
    OR NEW."watermark_at" IS NOT NULL
  ))
  OR (NEW."backlog_count" > 0 AND (
    NEW."consecutive_nonzero_samples" <> 1
    OR NEW."nonzero_since_at" <> NEW."metric_sampled_at"
  ))
BEGIN
  SELECT RAISE(ABORT, 'invalid initial alert runtime status');
END;

CREATE TRIGGER "alert_runtime_status_transition_guard"
BEFORE UPDATE ON "alert_runtime_status"
WHEN NEW."component" <> OLD."component"
  OR NEW."revision" <> OLD."revision" + 1
  OR NEW."updated_at" <= OLD."updated_at"
  OR NOT (
    (OLD."lease_id" IS NULL
      AND NEW."lease_id" IS NULL
      AND NEW."generation" = OLD."generation")
    OR (OLD."lease_id" IS NULL
      AND NEW."lease_id" IS NOT NULL
      AND NEW."generation" = OLD."generation" + 1)
    OR (OLD."lease_id" IS NOT NULL
      AND NEW."lease_id" IS OLD."lease_id"
      AND NEW."generation" = OLD."generation"
      AND NEW."updated_at" < OLD."lease_expires_at"
      AND NEW."lease_expires_at" >= OLD."lease_expires_at")
    OR (OLD."lease_id" IS NOT NULL
      AND NEW."lease_id" IS NULL
      AND NEW."generation" = OLD."generation"
      AND NEW."updated_at" < OLD."lease_expires_at")
    OR (OLD."lease_id" IS NOT NULL
      AND NEW."lease_id" IS NOT NULL
      AND NEW."lease_id" IS NOT OLD."lease_id"
      AND NEW."generation" = OLD."generation" + 1
      AND NEW."updated_at" >= OLD."lease_expires_at")
  )
  OR (OLD."last_started_at" IS NOT NULL AND (
    NEW."last_started_at" IS NULL
    OR NEW."last_started_at" < OLD."last_started_at"
  ))
  OR (OLD."last_success_at" IS NOT NULL AND (
    NEW."last_success_at" IS NULL
    OR NEW."last_success_at" < OLD."last_success_at"
  ))
  OR (OLD."last_error_at" IS NOT NULL AND (
    NEW."last_error_at" IS NULL
    OR NEW."last_error_at" < OLD."last_error_at"
  ))
  OR (OLD."watermark_at" IS NOT NULL AND (
    NEW."watermark_at" IS NULL
    OR NEW."watermark_at" < OLD."watermark_at"
  ))
  OR NOT (
    (NEW."last_error_at" IS OLD."last_error_at"
      AND NEW."last_error_code" IS OLD."last_error_code")
    OR (NEW."last_error_at" IS NOT NULL
      AND (OLD."last_error_at" IS NULL
        OR NEW."last_error_at" > OLD."last_error_at")
      AND NEW."last_error_code" IS NOT NULL)
  )
  OR (NEW."last_success_at" IS NOT OLD."last_success_at" AND (
    NEW."last_started_at" IS NULL
    OR NEW."last_success_at" < NEW."last_started_at"
  ))
  OR (NEW."last_error_at" IS NOT OLD."last_error_at" AND (
    NEW."last_started_at" IS NULL
    OR NEW."last_error_at" < NEW."last_started_at"
  ))
  OR (OLD."metric_sampled_at" IS NOT NULL
    AND NEW."metric_sampled_at" IS NULL)
  OR (OLD."metric_sampled_at" IS NOT NULL
    AND NEW."metric_sampled_at" IS NOT NULL
    AND NEW."metric_sampled_at" < OLD."metric_sampled_at")
  OR NOT (
    (NEW."metric_sampled_at" IS OLD."metric_sampled_at"
      AND NEW."backlog_count" IS OLD."backlog_count"
      AND NEW."backlog_bytes" IS OLD."backlog_bytes"
      AND NEW."oldest_message_age_seconds"
        IS OLD."oldest_message_age_seconds"
      AND NEW."nonzero_since_at" IS OLD."nonzero_since_at"
      AND NEW."consecutive_nonzero_samples"
        IS OLD."consecutive_nonzero_samples")
    OR (NEW."metric_sampled_at" IS NOT NULL
      AND (OLD."metric_sampled_at" IS NULL
        OR NEW."metric_sampled_at" > OLD."metric_sampled_at")
      AND (
        (NEW."backlog_count" = 0
          AND NEW."nonzero_since_at" IS NULL
          AND NEW."consecutive_nonzero_samples" = 0)
        OR (NEW."backlog_count" > 0 AND (
          (OLD."metric_sampled_at" IS NOT NULL
            AND OLD."backlog_count" > 0
            AND NEW."metric_sampled_at" = strftime(
              '%Y-%m-%dT%H:%M:%fZ',
              OLD."metric_sampled_at",
              '+60 seconds'
            )
            AND NEW."nonzero_since_at" = OLD."nonzero_since_at"
            AND NEW."consecutive_nonzero_samples"
              = OLD."consecutive_nonzero_samples" + 1)
          OR ((OLD."metric_sampled_at" IS NULL
              OR OLD."backlog_count" = 0
              OR NEW."metric_sampled_at" <> strftime(
                '%Y-%m-%dT%H:%M:%fZ',
                OLD."metric_sampled_at",
                '+60 seconds'
              ))
            AND NEW."nonzero_since_at" = NEW."metric_sampled_at"
            AND NEW."consecutive_nonzero_samples" = 1)
        ))
      ))
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid alert runtime status transition');
END;

-- The repository creates this anchor only after its first controlled evaluator
-- success. SQL proves an immutable persisted transition tied to the exact
-- current runtime row; it does not attest that external evaluator work ran.
CREATE TABLE "alert_evaluator_bootstrap" (
  "component" text PRIMARY KEY NOT NULL CHECK ("component" = 'evaluator'),
  "first_success_at" date NOT NULL CHECK (
    typeof("first_success_at") = 'text'
    AND length("first_success_at") = 24
    AND strftime(
      '%Y-%m-%dT%H:%M:%fZ', "first_success_at", '+0 seconds'
    ) IS NOT NULL
    AND strftime(
      '%Y-%m-%dT%H:%M:%fZ', "first_success_at", '+0 seconds'
    )
      = "first_success_at"
  ),
  "source_generation" integer NOT NULL CHECK (
    typeof("source_generation") = 'integer'
    AND "source_generation" BETWEEN 1 AND 1000000
  ),
  "source_revision" integer NOT NULL CHECK (
    typeof("source_revision") = 'integer'
    AND "source_revision" BETWEEN 1 AND 1000000000
  ),
  FOREIGN KEY ("component") REFERENCES "alert_runtime_status" ("component")
    ON DELETE RESTRICT
);

CREATE TRIGGER "alert_evaluator_bootstrap_insert_guard"
BEFORE INSERT ON "alert_evaluator_bootstrap"
WHEN EXISTS (SELECT 1 FROM "alert_evaluator_bootstrap")
  OR NOT EXISTS (
    SELECT 1
      FROM "alert_runtime_status" AS runtime
     WHERE runtime."component" = 'evaluator'
       AND runtime."component" = NEW."component"
       AND runtime."status" = 'healthy'
       AND runtime."last_started_at" IS NOT NULL
       AND runtime."last_success_at" = NEW."first_success_at"
       AND runtime."generation" = NEW."source_generation"
       AND runtime."revision" = NEW."source_revision"
  )
BEGIN
  SELECT RAISE(ABORT, 'evaluator bootstrap must match controlled runtime success');
END;

CREATE TRIGGER "alert_evaluator_bootstrap_update_guard"
BEFORE UPDATE ON "alert_evaluator_bootstrap"
BEGIN
  SELECT RAISE(ABORT, 'evaluator bootstrap is immutable');
END;

CREATE TRIGGER "alert_evaluator_bootstrap_delete_guard"
BEFORE DELETE ON "alert_evaluator_bootstrap"
BEGIN
  SELECT RAISE(ABORT, 'evaluator bootstrap is immutable');
END;

CREATE INDEX "alert_runtime_status_operator_idx"
  ON "alert_runtime_status" ("status", "updated_at" DESC);

-- Existing audit IDs are random UUIDs, and some guarded mutations deliberately
-- delete an audit row when a later statement cannot commit. A monotonic archive
-- cursor therefore belongs to the separately reviewed 0021 archive ledger, not
-- to this migration. This additive index supports bounded rule/type/subject/time
-- windows without changing audit-event write or retention semantics.
CREATE INDEX "audit_event_type_subject_time_bounded_idx"
  ON "audit_event" ("event_type", "subject_id", "occurred_at" DESC, "id");

CREATE INDEX "audit_event_time_bounded_idx"
  ON "audit_event" ("occurred_at" DESC, "id");

CREATE INDEX "audit_event_type_time_bounded_idx"
  ON "audit_event" ("event_type", "occurred_at" DESC, "id");

CREATE INDEX "audit_event_type_actor_time_bounded_idx"
  ON "audit_event" (
    "event_type", "occurred_at" DESC, "actor_ref", "actor_user_id", "id"
  );

CREATE INDEX "oauth_client_report_time_client_reason_reporter_bounded_idx"
  ON "oauth_client_report" (
    "created_at" DESC, "client_id", "reason", "reporter_ref",
    "reporter_user_id", "id"
  );

CREATE INDEX "logout_delivery_time_client_status_bounded_idx"
  ON "logout_delivery" ("created_at" DESC, "client_id", "status", "id");

CREATE INDEX "logout_delivery_status_client_time_bounded_idx"
  ON "logout_delivery" ("status", "client_id", "created_at", "id");

CREATE INDEX "logout_delivery_attempt_completion_bounded_idx"
  ON "logout_delivery_attempt" (
    "completed_at" DESC, "outcome", "delivery_id"
  );
