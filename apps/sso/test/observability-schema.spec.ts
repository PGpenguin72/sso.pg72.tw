import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import { deriveAlertReferenceV1 } from "../worker/alert-rules";
import { ALERT_AUDIT_TIMESTAMP_INTEGRITY_QUERY } from "../worker/alert-audit-source-repository";
import { ALERT_OAUTH_TIMESTAMP_INTEGRITY_QUERY } from "../worker/alert-oauth-source-repository";
import {
  acquireAlertEvaluatorRun,
  bindAlertEvaluatorRunAsOf,
  recordAlertEvaluatorRunFailure,
  recordAlertEvaluatorRunSource,
  recordAlertEvaluatorRunSuccess,
  sealAlertEvaluatorRunPlan,
} from "../worker/alert-run-repository";
import { ALERT_EVALUATOR_SOURCE_IDS } from "../worker/alert-run-proof";

const NOW = "2026-07-17T10:00:00.000Z";
let evaluationTick = 0;

const ALERT_TIMESTAMP_COLUMNS = [
  { table: "alert_hash_key_sentinel", columns: ["created_at"] },
  {
    table: "alert_state",
    columns: [
      "cooldown_until",
      "last_evaluated_at",
      "last_breached_at",
      "last_cleared_at",
      "last_notification_scheduled_at",
      "created_at",
      "updated_at",
    ],
  },
  {
    table: "security_alert",
    columns: [
      "first_seen_at",
      "last_seen_at",
      "acknowledged_at",
      "resolved_at",
      "created_at",
      "updated_at",
    ],
  },
  {
    table: "alert_outbox",
    columns: [
      "first_seen_at",
      "last_seen_at",
      "next_attempt_at",
      "lease_expires_at",
      "accepted_at",
      "dead_at",
      "created_at",
      "updated_at",
    ],
  },
  {
    table: "alert_delivery_attempt",
    columns: ["started_at", "completed_at"],
  },
  {
    table: "alert_runtime_status",
    columns: [
      "lease_expires_at",
      "last_started_at",
      "last_success_at",
      "last_error_at",
      "metric_sampled_at",
      "nonzero_since_at",
      "watermark_at",
      "updated_at",
    ],
  },
  { table: "alert_evaluator_bootstrap", columns: ["first_success_at"] },
] as const;

function nextEvaluationTime(): string {
  evaluationTick += 1;
  return new Date(Date.parse(NOW) + evaluationTick * 1000).toISOString();
}

function cooldownAfter(evaluatedAt: string): string {
  return new Date(Date.parse(evaluatedAt) + 30 * 60 * 1000).toISOString();
}

function encodeBase64url32(bytes: Uint8Array): string {
  if (bytes.byteLength !== 32) throw new Error("expected exactly 32 bytes");
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function opaque43(): string {
  return encodeBase64url32(crypto.getRandomValues(new Uint8Array(32)));
}

function nonCanonical43(): string {
  return `${"A".repeat(42)}B`;
}

function deliveryKey(character = "D"): string {
  return `pgid_ad_${character.repeat(42)}A`;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function insertAlertState(
  options: {
    breachSeverity?: "warning" | "critical" | null;
    consecutiveBreaches?: number;
    consecutiveClears?: number;
    cooldownUntil?: string | null;
    criticalThreshold?: number | null;
    currentSeverity?: "none" | "warning" | "critical";
    dedupeKey?: string;
    generation?: number;
    hashVersion?: number | null;
    lastNotificationScheduledAt?: string | null;
    metricKind?: string;
    metricName?: string;
    metricUnit?: string;
    minimumSampleCount?: number;
    minimumNumeratorCount?: number | null;
    observedDenominator?: number | null;
    observedNumerator?: number | null;
    observedValue?: number;
    provider?: string | null;
    queueName?: string | null;
    reason?: string | null;
    ruleId?: string;
    revision?: number;
    secondaryMetricKind?: string | null;
    secondaryMetricName?: string | null;
    secondaryMetricUnit?: string | null;
    secondaryObservedValue?: number | null;
    secondaryThreshold?: number | null;
    sourceKind?: "d1_exact" | "queue_approximate";
    subjectRef?: string | null;
    surface?: string | null;
    warningThreshold?: number | null;
  } = {},
): Promise<string> {
  const id = crypto.randomUUID();
  const warningThreshold = options.warningThreshold === undefined
    ? 10
    : options.warningThreshold;
  const criticalThreshold = options.criticalThreshold === undefined
    ? 40
    : options.criticalThreshold;
  const breachSeverity = options.breachSeverity === undefined
    ? warningThreshold === null ? "critical" : "warning"
    : options.breachSeverity;
  const consecutiveBreaches = options.consecutiveBreaches ??
    (breachSeverity === null ? 0 : 1);
  await env.PG72_ID_DB.prepare(
    `INSERT INTO alert_state
      (id, rule_id, environment, source_kind, dedupe_key, subject_ref, hash_version,
       provider, queue_name, reason, surface,
       window_seconds, metric_name, metric_kind, metric_unit, observed_value,
       observed_numerator, observed_denominator, minimum_sample_count,
       minimum_numerator_count, warning_threshold, critical_threshold,
       secondary_metric_name, secondary_metric_kind, secondary_metric_unit,
       secondary_observed_value, secondary_threshold,
       consecutive_breaches, breach_severity, consecutive_clears,
       current_severity, generation, revision, cooldown_until,
       last_notification_scheduled_at,
       last_evaluated_at, created_at, updated_at)
     VALUES (?, ?, 'local', ?, ?, ?, ?, ?, ?, ?, ?, 900,
             ?, ?, ?, ?,
             ?, ?, ?, ?,
             ?, ?,
             ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?,
             ?, ?, ?)`,
  )
    .bind(
      id,
      options.ruleId ?? "pgid.registration.denied.v1",
      options.sourceKind ?? "d1_exact",
      options.dedupeKey ?? opaque43(),
      options.subjectRef ?? null,
      options.hashVersion ?? null,
      options.provider ?? null,
      options.queueName ?? null,
      options.reason ?? null,
      options.surface ?? null,
      options.metricName ?? "count",
      options.metricKind ?? "count",
      options.metricUnit ?? "events",
      options.observedValue ?? 12,
      options.observedNumerator ?? null,
      options.observedDenominator ?? null,
      options.minimumSampleCount ?? 0,
      options.minimumNumeratorCount ?? null,
      warningThreshold,
      criticalThreshold,
      options.secondaryMetricName ?? null,
      options.secondaryMetricKind ?? null,
      options.secondaryMetricUnit ?? null,
      options.secondaryObservedValue ?? null,
      options.secondaryThreshold ?? null,
      consecutiveBreaches,
      breachSeverity,
      options.consecutiveClears ?? 0,
      options.currentSeverity ?? "none",
      options.generation ?? 0,
      options.revision ?? 0,
      options.cooldownUntil ?? null,
      options.lastNotificationScheduledAt ?? null,
      NOW,
      NOW,
      NOW,
    )
    .run();
  return id;
}

async function insertTransientAlertState(
  options: Parameters<typeof insertAlertState>[0] = {},
): Promise<string> {
  const id = await insertAlertState(options);
  await env.PG72_ID_DB.prepare("DELETE FROM alert_state WHERE id = ?")
    .bind(id)
    .run();
  return id;
}

async function insertSecurityAlert(
  stateId: string,
  generation = 1,
  options: {
    acknowledgedAt?: string | null;
    acknowledgedByHashVersion?: number | null;
    acknowledgedByRef?: string | null;
    environment?: "local" | "preview" | "production";
    metricKind?: string;
    metricName?: string;
    metricUnit?: string;
    minimumNumeratorCount?: number | null;
    minimumSampleCount?: number;
    observedDenominator?: number | null;
    observedNumerator?: number | null;
    observedValue?: number;
    ruleId?: string;
    resolvedAt?: string | null;
    resolvedByHashVersion?: number | null;
    resolvedByRef?: string | null;
    resolutionCode?: string | null;
    secondaryMetricKind?: string | null;
    secondaryMetricName?: string | null;
    secondaryMetricUnit?: string | null;
    secondaryObservedValue?: number | null;
    secondaryThreshold?: number | null;
    severity?: "warning" | "critical";
    sourceKind?: "d1_exact" | "queue_approximate";
    status?: "open" | "acknowledged" | "resolved";
    threshold?: number;
  } = {},
): Promise<string> {
  const id = crypto.randomUUID();
  const severity = options.severity ?? "warning";
  const insert = env.PG72_ID_DB.prepare(
    `INSERT INTO security_alert
      (id, state_id, rule_id, environment, generation, severity, status,
       first_seen_at, last_seen_at,
       source_kind, window_seconds, metric_name, metric_kind, metric_unit,
       observed_value, observed_numerator, observed_denominator,
       minimum_sample_count, minimum_numerator_count, threshold,
       secondary_metric_name, secondary_metric_kind, secondary_metric_unit,
       secondary_observed_value, secondary_threshold,
       acknowledged_at, acknowledged_by_ref, acknowledged_by_hash_version,
       resolved_at, resolved_by_ref, resolved_by_hash_version, resolution_code,
       created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 900,
             ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id,
      stateId,
      options.ruleId ?? "pgid.registration.denied.v1",
      options.environment ?? "local",
      generation,
      severity,
      options.status ?? "open",
      NOW,
      NOW,
      options.sourceKind ?? "d1_exact",
      options.metricName ?? "count",
      options.metricKind ?? "count",
      options.metricUnit ?? "events",
      options.observedValue ?? 12,
      options.observedNumerator ?? null,
      options.observedDenominator ?? null,
      options.minimumSampleCount ?? 0,
      options.minimumNumeratorCount ?? null,
      options.threshold ?? 10,
      options.secondaryMetricName ?? null,
      options.secondaryMetricKind ?? null,
      options.secondaryMetricUnit ?? null,
      options.secondaryObservedValue ?? null,
      options.secondaryThreshold ?? null,
      options.acknowledgedAt ?? null,
      options.acknowledgedByRef ?? null,
      options.acknowledgedByHashVersion ?? null,
      options.resolvedAt ?? null,
      options.resolvedByRef ?? null,
      options.resolvedByHashVersion ?? null,
      options.resolutionCode ?? null,
      NOW,
      NOW,
    );
  const state = await env.PG72_ID_DB.prepare(
    `SELECT generation, current_severity, breach_severity, consecutive_breaches
       FROM alert_state WHERE id = ?`,
  )
    .bind(stateId)
    .first<{
      breach_severity: string | null;
      consecutive_breaches: number;
      current_severity: string;
      generation: number;
    }>();
  if (
    state?.current_severity === "none" &&
    state.generation === generation - 1
  ) {
    const candidateAt = nextEvaluationTime();
    const confirmedAt = nextEvaluationTime();
    const candidate = env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET breach_severity = ?, consecutive_breaches = 1,
              consecutive_clears = 0, revision = revision + 1,
              last_evaluated_at = ?, updated_at = ?
        WHERE id = ? AND current_severity = 'none' AND generation = ?`,
    ).bind(severity, candidateAt, candidateAt, stateId, generation - 1);
    const confirm = env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET current_severity = ?, generation = generation + 1,
              revision = revision + 1, consecutive_breaches = 0,
              breach_severity = NULL, consecutive_clears = 0,
              cooldown_until = NULL, last_notification_scheduled_at = ?,
              last_breached_at = ?, last_evaluated_at = ?, updated_at = ?
        WHERE id = ? AND current_severity = 'none' AND generation = ?`,
    ).bind(
      severity,
      NOW,
      NOW,
      confirmedAt,
      confirmedAt,
      stateId,
      generation - 1,
    );
    if (
      state.breach_severity === severity &&
      state.consecutive_breaches === 1
    ) {
      await env.PG72_ID_DB.batch([confirm, insert]);
    } else {
      await env.PG72_ID_DB.batch([candidate, confirm, insert]);
    }
  } else {
    await insert.run();
  }
  return id;
}

async function recordFourClearSamples(stateId: string): Promise<void> {
  const clearSamples = [1, 2, 3, 4].map((count) => {
    const evaluatedAt = nextEvaluationTime();
    return env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET consecutive_breaches = 0, breach_severity = NULL,
              consecutive_clears = ?, revision = revision + 1,
              last_evaluated_at = ?, updated_at = ?
        WHERE id = ? AND current_severity IN ('warning', 'critical')`,
    ).bind(count, evaluatedAt, evaluatedAt, stateId);
  });
  await env.PG72_ID_DB.batch(clearSamples);
}

async function clearAlertState(stateId: string): Promise<void> {
  await recordFourClearSamples(stateId);
  const clearedAt = nextEvaluationTime();
  const fifthClear = env.PG72_ID_DB.prepare(
    `UPDATE alert_state
        SET current_severity = 'none', consecutive_clears = 0,
            revision = revision + 1, last_notification_scheduled_at = NULL,
            cooldown_until = ?, last_cleared_at = ?,
            last_evaluated_at = ?, updated_at = ?
      WHERE id = ? AND current_severity IN ('warning', 'critical')`,
  ).bind(cooldownAfter(clearedAt), NOW, clearedAt, clearedAt, stateId);
  await fifthClear.run();
}

async function expireAlertCooldown(stateId: string): Promise<void> {
  const cooldownUntil = await env.PG72_ID_DB.prepare(
    "SELECT cooldown_until FROM alert_state WHERE id = ?",
  )
    .bind(stateId)
    .first<string>("cooldown_until");
  expect(cooldownUntil).not.toBeNull();
  evaluationTick = Math.max(
    evaluationTick,
    (Date.parse(cooldownUntil!) - Date.parse(NOW)) / 1000,
  );
  await env.PG72_ID_DB.prepare(
    `UPDATE alert_state
        SET cooldown_until = NULL, revision = revision + 1,
            last_evaluated_at = ?, updated_at = ?
      WHERE id = ?`,
  )
    .bind(cooldownUntil, cooldownUntil, stateId)
    .run();
}

interface OutboxOptions {
  acceptedAt?: string | null;
  alertId: string;
  attempts?: number;
  channel?: "email" | "webhook";
  deliveryKey?: string;
  deadAt?: string | null;
  eventKind?: "opened" | "reminder" | "escalated" | "resolved";
  eventSequence?: number;
  environment?: "local" | "preview" | "production";
  generation?: number;
  hashVersion?: number | null;
  idempotencyKey?: string;
  incidentStatus?: "open" | "acknowledged" | "resolved";
  lastErrorCode?: string | null;
  leaseExpiresAt?: string | null;
  leaseId?: string | null;
  metricKind?: string;
  metricName?: string;
  metricUnit?: string;
  minimumNumeratorCount?: number | null;
  minimumSampleCount?: number;
  nextAttemptAt?: string | null;
  observedDenominator?: number | null;
  observedNumerator?: number | null;
  observedValue?: number;
  provider?: string | null;
  queueName?: string | null;
  reason?: string | null;
  ruleId?: string;
  replayCount?: number;
  severity?: "warning" | "critical";
  secondaryMetricKind?: string | null;
  secondaryMetricName?: string | null;
  secondaryMetricUnit?: string | null;
  secondaryObservedValue?: number | null;
  secondaryThreshold?: number | null;
  sourceKind?: "d1_exact" | "queue_approximate";
  status?: "pending" | "processing" | "retry" | "accepted" | "dead";
  subjectRef?: string | null;
  surface?: string | null;
  threshold?: number;
}

async function insertOutbox(options: OutboxOptions): Promise<number> {
  const resolvedDeliveryKey = options.deliveryKey ?? deliveryKey();
  const status = options.status ?? "pending";
  const eventKind = options.eventKind ?? "opened";
  const channel = options.channel ?? "email";
  const generation = options.generation ?? 1;
  const eventSequence = options.eventSequence ?? (eventKind === "reminder"
    ? await env.PG72_ID_DB.prepare(
      `SELECT coalesce(max(event_sequence) + 1, 1) AS next_sequence
         FROM alert_outbox
        WHERE alert_id = ? AND generation = ?
          AND event_kind = 'reminder' AND channel = ?`,
    )
      .bind(options.alertId, generation, channel)
      .first<number>("next_sequence") ?? 1
    : 1);
  const idempotencyKey = options.idempotencyKey ?? opaque43();
  const incidentStatus = options.incidentStatus ?? "open";
  const severity = options.severity ?? "warning";
  const ruleId = options.ruleId ?? "pgid.registration.denied.v1";
  const environment = options.environment ?? "local";
  const sourceKind = options.sourceKind ?? "d1_exact";
  const observedValue = options.observedValue ?? 12;
  const observedNumerator = options.observedNumerator ?? null;
  const observedDenominator = options.observedDenominator ?? null;
  const minimumSampleCount = options.minimumSampleCount ?? 0;
  const minimumNumeratorCount = options.minimumNumeratorCount ?? null;
  const metricName = options.metricName ?? "count";
  const metricKind = options.metricKind ?? "count";
  const metricUnit = options.metricUnit ?? "events";
  const threshold = options.threshold ?? 10;
  const secondaryMetricName = options.secondaryMetricName ?? null;
  const secondaryMetricKind = options.secondaryMetricKind ?? null;
  const secondaryMetricUnit = options.secondaryMetricUnit ?? null;
  const secondaryObservedValue = options.secondaryObservedValue ?? null;
  const secondaryThreshold = options.secondaryThreshold ?? null;
  const subjectRef = options.subjectRef ?? null;
  const hashVersion = options.hashVersion ?? null;
  const provider = options.provider ?? null;
  const queueName = options.queueName ?? null;
  const reason = options.reason ?? null;
  const surface = options.surface ?? null;
  const payload = JSON.stringify({
    schemaVersion: 1,
    templateVersion: 1,
    incidentId: options.alertId,
    generation,
    deliveryId: resolvedDeliveryKey,
    idempotencyKey,
    eventKind,
    eventSequence,
    channel,
    rule: ruleId,
    environment,
    sourceKind,
    severity,
    status: incidentStatus,
    firstSeenAt: NOW,
    lastSeenAt: NOW,
    windowSeconds: 900,
    metricName,
    metricKind,
    metricUnit,
    observedValue,
    observedNumerator,
    observedDenominator,
    minimumSampleCount,
    minimumNumeratorCount,
    threshold,
    secondaryMetricName,
    secondaryMetricKind,
    secondaryMetricUnit,
    secondaryObservedValue,
    secondaryThreshold,
    subjectRef,
    hashVersion,
    provider,
    queue: queueName,
    reason,
    surface,
  });
  await env.PG72_ID_DB.prepare(
    `INSERT INTO alert_outbox
      (delivery_key, alert_id, generation, event_kind, event_sequence, channel,
      idempotency_key, payload_json, payload_sha256, rule_id, environment,
       source_kind, severity, incident_status, subject_ref, hash_version,
       provider, queue_name, reason, surface,
       first_seen_at, last_seen_at, window_seconds,
       metric_name, metric_kind, metric_unit, observed_value,
       observed_numerator, observed_denominator, minimum_sample_count,
       minimum_numerator_count, threshold,
       secondary_metric_name, secondary_metric_kind, secondary_metric_unit,
       secondary_observed_value, secondary_threshold,
       status, attempts, replay_count, next_attempt_at, lease_id, lease_expires_at,
       accepted_at, dead_at, last_error_code, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 900,
             ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      resolvedDeliveryKey,
      options.alertId,
      generation,
      eventKind,
      eventSequence,
      channel,
      idempotencyKey,
      payload,
      await sha256Hex(payload),
      ruleId,
      environment,
      sourceKind,
      severity,
      incidentStatus,
      subjectRef,
      hashVersion,
      provider,
      queueName,
      reason,
      surface,
      NOW,
      NOW,
      metricName,
      metricKind,
      metricUnit,
      observedValue,
      observedNumerator,
      observedDenominator,
      minimumSampleCount,
      minimumNumeratorCount,
      threshold,
      secondaryMetricName,
      secondaryMetricKind,
      secondaryMetricUnit,
      secondaryObservedValue,
      secondaryThreshold,
      status,
      options.attempts ?? (status === "pending" ? 0 : 1),
      options.replayCount ?? 0,
      options.nextAttemptAt === undefined
        ? status === "pending" || status === "retry"
          ? NOW
          : null
        : options.nextAttemptAt,
      options.leaseId ?? null,
      options.leaseExpiresAt ?? null,
      options.acceptedAt ?? null,
      options.deadAt ?? null,
      options.lastErrorCode ?? null,
      NOW,
      NOW,
    )
    .run();
  const row = await env.PG72_ID_DB.prepare(
    "SELECT id FROM alert_outbox WHERE delivery_key = ?",
  )
    .bind(resolvedDeliveryKey)
    .first<{ id: number }>();
  expect(row).not.toBeNull();
  return row!.id;
}

async function claimOutbox(
  outboxId: number,
  leaseId: string,
  leaseExpiresAt = "2026-07-17T10:01:00.000Z",
  claimedAt = NOW,
): Promise<void> {
  await env.PG72_ID_DB.prepare(
    `UPDATE alert_outbox
        SET status = 'processing', attempts = attempts + 1,
            next_attempt_at = NULL, lease_id = ?, lease_expires_at = ?,
            updated_at = ?
      WHERE id = ?`,
  )
    .bind(leaseId, leaseExpiresAt, claimedAt, outboxId)
    .run();
}

describe("alert observability migration", () => {
  beforeEach(async () => {
    evaluationTick = 0;
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare("DELETE FROM alert_delivery_attempt"),
      env.PG72_ID_DB.prepare("DELETE FROM alert_outbox"),
      env.PG72_ID_DB.prepare("DELETE FROM security_alert"),
      env.PG72_ID_DB.prepare("DELETE FROM alert_state"),
      env.PG72_ID_DB.prepare("DELETE FROM alert_runtime_status"),
    ]);
  });

  it("applies alert schema, continuity sentinel, and bounded source indexes", async () => {
    const schema = await env.PG72_ID_DB.prepare(
      `SELECT type, name, sql
         FROM sqlite_schema
        WHERE name IN (
          'alert_state', 'security_alert', 'alert_outbox',
          'alert_delivery_attempt', 'alert_evaluator_bootstrap',
          'alert_runtime_status',
          'alert_hash_key_sentinel', 'alert_state_semantic_identity_idx',
          'alert_state_tracked_evaluation_idx',
          'alert_outbox_due_idx', 'security_alert_unresolved_state_idx',
          'audit_event_invalid_occurred_at_idx',
          'audit_event_occurred_at_insert_guard',
          'audit_event_occurred_at_update_guard',
          'audit_event_time_bounded_idx',
          'audit_event_type_actor_time_bounded_idx',
          'audit_event_type_subject_time_bounded_idx',
          'audit_event_type_time_bounded_idx',
          'oauth_client_report_created_at_insert_guard',
          'oauth_client_report_created_at_update_guard',
          'oauth_client_report_invalid_created_at_idx',
          'oauth_client_report_time_client_reason_reporter_bounded_idx',
          'logout_delivery_time_client_status_bounded_idx',
          'logout_delivery_status_client_time_bounded_idx',
          'logout_delivery_attempt_completion_bounded_idx',
          'logout_delivery_invalid_created_at_bounded_idx',
          'logout_delivery_attempt_invalid_completed_at_bounded_idx',
          'logout_delivery_created_at_insert_guard',
          'logout_delivery_created_at_update_guard',
          'logout_delivery_attempt_completed_at_insert_guard',
          'logout_delivery_attempt_completed_at_update_guard'
        )
        ORDER BY name`,
    ).all<{ name: string; sql: string; type: string }>();
    expect(schema.results.map(({ name }) => name)).toEqual([
      "alert_delivery_attempt",
      "alert_evaluator_bootstrap",
      "alert_hash_key_sentinel",
      "alert_outbox",
      "alert_outbox_due_idx",
      "alert_runtime_status",
      "alert_state",
      "alert_state_semantic_identity_idx",
      "alert_state_tracked_evaluation_idx",
      "audit_event_invalid_occurred_at_idx",
      "audit_event_occurred_at_insert_guard",
      "audit_event_occurred_at_update_guard",
      "audit_event_time_bounded_idx",
      "audit_event_type_actor_time_bounded_idx",
      "audit_event_type_subject_time_bounded_idx",
      "audit_event_type_time_bounded_idx",
      "logout_delivery_attempt_completed_at_insert_guard",
      "logout_delivery_attempt_completed_at_update_guard",
      "logout_delivery_attempt_completion_bounded_idx",
      "logout_delivery_attempt_invalid_completed_at_bounded_idx",
      "logout_delivery_created_at_insert_guard",
      "logout_delivery_created_at_update_guard",
      "logout_delivery_invalid_created_at_bounded_idx",
      "logout_delivery_status_client_time_bounded_idx",
      "logout_delivery_time_client_status_bounded_idx",
      "oauth_client_report_created_at_insert_guard",
      "oauth_client_report_created_at_update_guard",
      "oauth_client_report_invalid_created_at_idx",
      "oauth_client_report_time_client_reason_reporter_bounded_idx",
      "security_alert",
      "security_alert_unresolved_state_idx",
    ]);
    for (const table of [
      "alert_delivery_attempt",
      "alert_evaluator_bootstrap",
      "alert_hash_key_sentinel",
      "alert_outbox",
      "alert_runtime_status",
      "alert_state",
      "security_alert",
    ]) {
      expect(schema.results.find(({ name }) => name === table)?.sql).toContain(
        "typeof(",
      );
    }
    const alertSchemaSql = schema.results
      .filter(({ type }) => type === "table")
      .map(({ sql }) => sql)
      .join("\n");
    expect(alertSchemaSql).not.toContain(`${"unix"}epoch(`);
    expect(alertSchemaSql).toContain("length(\"updated_at\") = 24");
    expect(alertSchemaSql).toContain("%Y-%m-%dT%H:%M:%fZ");
    expect(
      ALERT_TIMESTAMP_COLUMNS.flatMap(({ columns }) => columns),
    ).toHaveLength(33);
    for (const { table, columns } of ALERT_TIMESTAMP_COLUMNS) {
      const tableSql = schema.results.find(({ name }) => name === table)?.sql;
      expect(tableSql).toBeDefined();
      const tableInfo = await env.PG72_ID_DB.prepare(
        `PRAGMA table_info("${table}")`,
      ).all<{ name: string; type: string }>();
      expect(
        tableInfo.results
          .filter(({ type }) => type.toLowerCase() === "date")
          .map(({ name }) => name),
      ).toEqual([...columns]);
      for (const column of columns) {
        const formatterPattern = String.raw`strftime\s*\(\s*'%Y-%m-%dT%H:%M:%fZ'\s*,\s*"${column}"\s*,\s*'\+0 seconds'\s*\)`;
        expect(tableSql).toMatch(
          new RegExp(
            String.raw`typeof\s*\(\s*"${column}"\s*\)\s*=\s*'text'`,
          ),
        );
        expect(tableSql).toMatch(
          new RegExp(String.raw`length\s*\(\s*"${column}"\s*\)\s*=\s*24`),
        );
        expect(tableSql).toMatch(
          new RegExp(`${formatterPattern}\\s+IS NOT NULL`),
        );
        expect(tableSql).toMatch(
          new RegExp(`${formatterPattern}\\s*=\\s*"${column}"`),
        );
      }
    }
    expect(
      schema.results.find(({ name }) => name === "alert_outbox_due_idx")?.sql,
    ).toContain('("status", "next_attempt_at", "lease_expires_at")');
    expect(
      schema.results.find(
        ({ name }) => name === "security_alert_unresolved_state_idx",
      )?.sql,
    ).toContain("WHERE \"status\" IN ('open', 'acknowledged')");
    const trackedStateIndex = schema.results.find(
      ({ name }) => name === "alert_state_tracked_evaluation_idx",
    )?.sql;
    expect(trackedStateIndex).toMatch(
      /\(\s*"environment", "rule_id", "subject_ref", "hash_version"\s*\)/,
    );
    expect(trackedStateIndex).toContain('WHERE "source_kind" = \'d1_exact\'');
    expect(trackedStateIndex).toContain('"subject_ref" IS NOT NULL');
    expect(trackedStateIndex).toContain('"consecutive_clears" > 0');
    const invalidDeliveryIndex = schema.results.find(
      ({ name }) => name === "logout_delivery_invalid_created_at_bounded_idx",
    )?.sql;
    expect(invalidDeliveryIndex).toContain('ON "logout_delivery" ("created_at")');
    expect(invalidDeliveryIndex).toContain("WHERE NOT");
    expect(invalidDeliveryIndex).toContain("%Y-%m-%dT%H:%M:%fZ");
    const invalidAttemptIndex = schema.results.find(
      ({ name }) =>
        name === "logout_delivery_attempt_invalid_completed_at_bounded_idx",
    )?.sql;
    expect(invalidAttemptIndex).toContain(
      'ON "logout_delivery_attempt" ("completed_at")',
    );
    expect(invalidAttemptIndex).toContain('"completed_at" IS NOT NULL');
    for (const name of [
      "logout_delivery_created_at_insert_guard",
      "logout_delivery_created_at_update_guard",
      "logout_delivery_attempt_completed_at_insert_guard",
      "logout_delivery_attempt_completed_at_update_guard",
    ]) {
      const trigger = schema.results.find((entry) => entry.name === name);
      expect(trigger?.type).toBe("trigger");
      expect(trigger?.sql).toContain("must be canonical");
      expect(trigger?.sql).toContain("%Y-%m-%dT%H:%M:%fZ");
      expect(trigger?.sql).toContain("IS NOT NULL");
      if (name.includes("completed_at")) {
        expect(trigger?.sql).toContain('NEW."completed_at" IS NOT NULL');
      } else {
        expect(trigger?.sql).toContain('typeof(NEW."created_at") = \'text\'');
      }
    }
    const actorPlan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN
       SELECT actor_ref, actor_user_id, occurred_at, id
         FROM audit_event INDEXED BY audit_event_type_actor_time_bounded_idx
        WHERE event_type = ? AND occurred_at >= ?
        ORDER BY occurred_at DESC
        LIMIT 100`,
    )
      .bind("admin.schema_test", "2026-07-17T09:00:00.000Z")
      .all<{ detail: string }>();
    expect(actorPlan.results.map(({ detail }) => detail).join("\n")).toContain(
      "USING COVERING INDEX audit_event_type_actor_time_bounded_idx",
    );
    const logoutPlan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN
       SELECT client_id, created_at, id
         FROM logout_delivery
         INDEXED BY logout_delivery_status_client_time_bounded_idx
        WHERE status IN ('pending', 'processing', 'retry', 'dead')
        LIMIT 100`,
    ).all<{ detail: string }>();
    expect(logoutPlan.results.map(({ detail }) => detail).join("\n")).toContain(
      "USING COVERING INDEX logout_delivery_status_client_time_bounded_idx",
    );
    const logoutAuditId = crypto.randomUUID();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO audit_event (id, event_type, outcome, occurred_at)
       VALUES (?, 'logout.schema_test', 'success', ?)`,
    )
      .bind(logoutAuditId, NOW)
      .run();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO logout_delivery
        (delivery_key, event_id, session_id, user_id, client_id, reason,
         status, attempts, created_at, updated_at)
       VALUES (?, ?, 'old-session', 'old-user', 'old-client', 'sign_out',
               'dead', 1, '2026-07-17T08:00:00.000Z', ?)`,
    )
      .bind("L".repeat(45), logoutAuditId, NOW)
      .run();
    const oldLogout = await env.PG72_ID_DB.prepare(
      `SELECT COUNT(*) AS count, MIN(created_at) AS oldest
         FROM logout_delivery
        WHERE status IN ('pending', 'processing', 'retry', 'dead')`,
    ).first<{ count: number; oldest: string }>();
    expect(oldLogout).toEqual({
      count: 1,
      oldest: "2026-07-17T08:00:00.000Z",
    });
    await env.PG72_ID_DB.prepare("DELETE FROM logout_delivery WHERE event_id = ?")
      .bind(logoutAuditId)
      .run();
    await env.PG72_ID_DB.prepare("DELETE FROM audit_event WHERE id = ?")
      .bind(logoutAuditId)
      .run();

    const reportColumns = await env.PG72_ID_DB.prepare(
      "PRAGMA table_info('oauth_client_report')",
    ).all<{ name: string }>();
    expect(reportColumns.results.map(({ name }) => name)).toEqual(
      expect.arrayContaining(["reporter_ref", "reporter_ref_hash_version"]),
    );
    const sourceUserId = crypto.randomUUID();
    const otherUserId = crypto.randomUUID();
    const insertUser = (id: string, email: string) =>
      env.PG72_ID_DB.prepare(
        `INSERT INTO user
          (id, name, email, emailVerified, createdAt, updatedAt, role, status)
         VALUES (?, 'Schema actor', ?, 1, ?, ?, 'user', 'active')`,
      ).bind(id, email, NOW, NOW);
    await env.PG72_ID_DB.batch([
      insertUser(sourceUserId, "schema-actor-a@example.invalid"),
      insertUser(otherUserId, "schema-actor-b@example.invalid"),
    ]);
    const provenanceKey = encodeBase64url32(
      Uint8Array.from({ length: 32 }, (_, index) => index + 11),
    );
    const subjectReference = await deriveAlertReferenceV1(
      provenanceKey,
      "subject_hmac",
      sourceUserId,
    );
    const reporterReference = await deriveAlertReferenceV1(
      provenanceKey,
      "reporter_hmac",
      sourceUserId,
    );
    const actorReference = await deriveAlertReferenceV1(
      provenanceKey,
      "actor_hmac",
      sourceUserId,
    );
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauth_client_report
          (id, reporter_user_id, client_id, reason, created_at, reporter_ref,
           reporter_ref_hash_version)
         VALUES (?, NULL, 'schema-stored-only-report', 'phishing', ?, ?, 1)`,
      )
        .bind(crypto.randomUUID(), NOW, reporterReference.value)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO audit_event
          (id, event_type, actor_user_id, outcome, occurred_at, actor_ref,
           actor_ref_hash_version)
         VALUES (?, 'admin.schema_stored_only', NULL, 'success', ?, ?, 1)`,
      )
        .bind(crypto.randomUUID(), NOW, subjectReference.value)
        .run(),
    ).rejects.toThrow();
    const reportId = crypto.randomUUID();
    const insertReport = (reporterRef: string | null, hashVersion: number | null) =>
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauth_client_report
          (id, reporter_user_id, client_id, reason, created_at, reporter_ref,
           reporter_ref_hash_version)
         VALUES (?, ?, 'schema-test-client', 'phishing', ?, ?, ?)`,
      )
        .bind(reportId, sourceUserId, NOW, reporterRef, hashVersion)
        .run();
    await expect(insertReport(opaque43(), null)).rejects.toThrow();
    await expect(insertReport(nonCanonical43(), 1)).rejects.toThrow();
    await insertReport(reporterReference.value, 1);
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE oauth_client_report
            SET reporter_user_id = NULL, reporter_ref = ?,
                reporter_ref_hash_version = 1
          WHERE id = ?`,
      )
        .bind(opaque43(), reportId)
        .run(),
    ).rejects.toThrow();
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT reporter_user_id, reporter_ref
           FROM oauth_client_report WHERE id = ?`,
      )
        .bind(reportId)
        .first<{ reporter_ref: string | null; reporter_user_id: string }>(),
    ).toEqual({
      reporter_ref: reporterReference.value,
      reporter_user_id: sourceUserId,
    });
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE oauth_client_report SET reporter_ref_hash_version = NULL
          WHERE id = ?`,
      )
        .bind(reportId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE oauth_client_report
            SET reporter_ref = NULL, reporter_ref_hash_version = NULL
          WHERE id = ?`,
      )
        .bind(reportId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE oauth_client_report SET reporter_user_id = ? WHERE id = ?",
      )
        .bind(otherUserId, reportId)
        .run(),
    ).rejects.toThrow();

    const auditColumns = await env.PG72_ID_DB.prepare(
      "PRAGMA table_info('audit_event')",
    ).all<{ name: string }>();
    expect(auditColumns.results.map(({ name }) => name)).toEqual(
      expect.arrayContaining(["actor_ref", "actor_ref_hash_version"]),
    );
    const actorEventId = crypto.randomUUID();
    const insertActorEvent = (actorRef: string | null, hashVersion: number | null) =>
      env.PG72_ID_DB.prepare(
        `INSERT INTO audit_event
          (id, event_type, actor_user_id, outcome, occurred_at, actor_ref,
           actor_ref_hash_version)
         VALUES (?, 'admin.schema_test', ?, 'success', ?, ?, ?)`,
      )
        .bind(actorEventId, sourceUserId, NOW, actorRef, hashVersion)
        .run();
    await expect(insertActorEvent(opaque43(), null)).rejects.toThrow();
    await expect(insertActorEvent(nonCanonical43(), 1)).rejects.toThrow();
    await insertActorEvent(actorReference.value, 1);
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE audit_event
            SET actor_user_id = NULL, actor_ref = ?, actor_ref_hash_version = 1
          WHERE id = ?`,
      )
        .bind(opaque43(), actorEventId)
        .run(),
    ).rejects.toThrow();
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT actor_user_id, actor_ref FROM audit_event WHERE id = ?",
      )
        .bind(actorEventId)
        .first<{ actor_ref: string | null; actor_user_id: string }>(),
    ).toEqual({
      actor_ref: actorReference.value,
      actor_user_id: sourceUserId,
    });
    const noRefReportId = crypto.randomUUID();
    const noRefActorEventId = crypto.randomUUID();
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauth_client_report
          (id, reporter_user_id, client_id, reason, created_at)
         VALUES (?, ?, 'schema-no-ref-client', 'phishing', ?)`,
      ).bind(noRefReportId, sourceUserId, NOW),
      env.PG72_ID_DB.prepare(
        `INSERT INTO audit_event
          (id, event_type, actor_user_id, outcome, occurred_at)
         VALUES (?, 'admin.schema_no_ref', ?, 'success', ?)`,
      ).bind(noRefActorEventId, sourceUserId, NOW),
    ]);
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE audit_event SET actor_ref_hash_version = NULL WHERE id = ?",
      )
        .bind(actorEventId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE audit_event SET actor_ref = NULL, actor_ref_hash_version = NULL
          WHERE id = ?`,
      )
        .bind(actorEventId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE audit_event SET actor_user_id = ? WHERE id = ?",
      )
        .bind(otherUserId, actorEventId)
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare("DELETE FROM user WHERE id = ?")
      .bind(sourceUserId)
      .run();
    const reportAfterDelete = await env.PG72_ID_DB.prepare(
      `SELECT reporter_user_id, reporter_ref
         FROM oauth_client_report WHERE id = ?`,
    )
      .bind(reportId)
      .first<{ reporter_ref: string; reporter_user_id: string | null }>();
    expect(reportAfterDelete?.reporter_user_id).toBeNull();
    expect(reportAfterDelete?.reporter_ref).toBe(reporterReference.value);
    const actorAfterDelete = await env.PG72_ID_DB.prepare(
      "SELECT actor_user_id, actor_ref FROM audit_event WHERE id = ?",
    )
      .bind(actorEventId)
      .first<{ actor_ref: string; actor_user_id: string | null }>();
    expect(actorAfterDelete?.actor_user_id).toBeNull();
    expect(actorAfterDelete?.actor_ref).toBe(actorReference.value);
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE oauth_client_report
            SET reporter_ref = ?, reporter_ref_hash_version = 1
          WHERE id = ?`,
      )
        .bind(opaque43(), noRefReportId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE audit_event
            SET actor_ref = ?, actor_ref_hash_version = 1
          WHERE id = ?`,
      )
        .bind(opaque43(), noRefActorEventId)
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare("DELETE FROM oauth_client_report WHERE id = ?")
      .bind(reportId)
      .run();
    await env.PG72_ID_DB.prepare("DELETE FROM audit_event WHERE id = ?")
      .bind(actorEventId)
      .run();
    await env.PG72_ID_DB.prepare("DELETE FROM oauth_client_report WHERE id = ?")
      .bind(noRefReportId)
      .run();
    await env.PG72_ID_DB.prepare("DELETE FROM audit_event WHERE id = ?")
      .bind(noRefActorEventId)
      .run();
    await env.PG72_ID_DB.prepare("DELETE FROM user WHERE id = ?")
      .bind(otherUserId)
      .run();

    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_hash_key_sentinel
          (id, domain, fingerprint_ref, hash_version, created_at)
         VALUES (1, 'pgid.alert_subject_hash_key.v1', ?, 1, ?)`,
      )
        .bind(nonCanonical43(), NOW)
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_hash_key_sentinel
        (id, domain, fingerprint_ref, hash_version, created_at)
       VALUES (1, 'pgid.alert_subject_hash_key.v1', ?, 1, ?)`,
    )
      .bind(opaque43(), NOW)
      .run();
    const originalFingerprint = await env.PG72_ID_DB.prepare(
      "SELECT fingerprint_ref FROM alert_hash_key_sentinel WHERE id = 1",
    ).first<string>("fingerprint_ref");
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO alert_hash_key_sentinel
          (id, domain, fingerprint_ref, hash_version, created_at)
         VALUES (1, 'pgid.alert_subject_hash_key.v1', ?, 1, ?)`,
      )
        .bind(opaque43(), NOW)
        .run(),
    ).rejects.toThrow();
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT fingerprint_ref FROM alert_hash_key_sentinel WHERE id = 1",
      ).first<string>("fingerprint_ref"),
    ).toBe(originalFingerprint);
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE alert_hash_key_sentinel SET fingerprint_ref = ? WHERE id = 1",
      )
        .bind(opaque43())
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare("DELETE FROM alert_hash_key_sentinel WHERE id = 1").run(),
    ).rejects.toThrow();

    const auditId = crypto.randomUUID();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO audit_event (id, event_type, outcome, occurred_at)
       VALUES (?, 'observability.schema_test', 'success', ?)`,
    )
      .bind(auditId, NOW)
      .run();
    await env.PG72_ID_DB.prepare("DELETE FROM audit_event WHERE id = ?")
      .bind(auditId)
      .run();
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT COUNT(*) AS count FROM audit_event WHERE id = ?",
      )
        .bind(auditId)
        .first<number>("count"),
    ).toBe(0);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT COUNT(*) AS count FROM sqlite_schema WHERE name = 'audit_event_sequence'",
      ).first<number>("count"),
    ).toBe(0);
  });

  it("guards canonical source times and keeps empty integrity probes covering", async () => {
    const invalidTimestamps = [
      "2032-02-04T12:30:00+01:00",
      "0001-01-01T00:30:00+01:00",
      "9998-12-31T23:30:00-01:00",
      "2025-02-29T00:00:00.000Z",
      "123456789",
    ];
    for (const [index, timestamp] of invalidTimestamps.entries()) {
      await expect(
        env.PG72_ID_DB.prepare(
          `INSERT INTO audit_event (id, event_type, outcome, occurred_at)
           VALUES (?, 'observability.time_guard', 'success', ?)`,
        )
          .bind(`time-guard-audit:${index}:${crypto.randomUUID()}`, timestamp)
          .run(),
      ).rejects.toThrow(/audit event timestamp must be canonical/);
      await expect(
        env.PG72_ID_DB.prepare(
          `INSERT INTO oauth_client_report
            (id, client_id, reason, status, created_at)
           VALUES (?, 'time-guard-client', 'other', 'open', ?)`,
        )
          .bind(`time-guard-oauth:${index}:${crypto.randomUUID()}`, timestamp)
          .run(),
      ).rejects.toThrow(/OAuth report timestamp must be canonical/);
    }

    const auditId = `time-guard-audit:${crypto.randomUUID()}`;
    const reportId = `time-guard-oauth:${crypto.randomUUID()}`;
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO audit_event (id, event_type, outcome, occurred_at)
         VALUES (?, 'observability.time_guard', 'success', ?)`,
      ).bind(auditId, "2032-02-04T11:30:00.000Z"),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauth_client_report
          (id, client_id, reason, status, created_at)
         VALUES (?, 'time-guard-client', 'other', 'open', ?)`,
      ).bind(reportId, "2032-02-04T11:30:00.000Z"),
    ]);
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE audit_event SET occurred_at = ? WHERE id = ?",
      )
        .bind(invalidTimestamps[0], auditId)
        .run(),
    ).rejects.toThrow(/audit event timestamp must be canonical/);
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE oauth_client_report SET created_at = ? WHERE id = ?",
      )
        .bind(invalidTimestamps[0], reportId)
        .run(),
    ).rejects.toThrow(/OAuth report timestamp must be canonical/);
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        "UPDATE audit_event SET occurred_at = ? WHERE id = ?",
      ).bind("2032-02-04T11:31:00.000Z", auditId),
      env.PG72_ID_DB.prepare(
        "UPDATE oauth_client_report SET created_at = ? WHERE id = ?",
      ).bind("2032-02-04T11:31:00.000Z", reportId),
    ]);

    for (const { column, index, query, table } of [
      {
        column: "occurred_at",
        index: "audit_event_invalid_occurred_at_idx",
        query: ALERT_AUDIT_TIMESTAMP_INTEGRITY_QUERY,
        table: "audit_event",
      },
      {
        column: "created_at",
        index: "oauth_client_report_invalid_created_at_idx",
        query: ALERT_OAUTH_TIMESTAMP_INTEGRITY_QUERY,
        table: "oauth_client_report",
      },
    ]) {
      const columns = await env.PG72_ID_DB.prepare(
        `PRAGMA index_info("${index}")`,
      ).all<{ name: string; seqno: number }>();
      expect(columns.results).toEqual([{ cid: expect.any(Number), name: column, seqno: 0 }]);
      const projection = await env.PG72_ID_DB.prepare(query)
        .first<number>("invalid_timestamp_exists");
      expect(projection).toBe(0);
      const plan = await env.PG72_ID_DB.prepare(
        `EXPLAIN QUERY PLAN ${query}`,
      ).all<{ detail: string }>();
      const details = plan.results.map(({ detail }) => detail).join("\n");
      expect(details).toContain(`USING COVERING INDEX ${index}`);
      expect(details).not.toMatch(new RegExp(`SCAN ${table}$`, "m"));
    }

    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare("DELETE FROM oauth_client_report WHERE id = ?")
        .bind(reportId),
      env.PG72_ID_DB.prepare("DELETE FROM audit_event WHERE id = ?")
        .bind(auditId),
    ]);
  });

  it("accepts every canonical tail produced by a real 32-byte encoding", async () => {
    const encodings = Array.from({ length: 16 }, (_, lowNibble) => {
      const bytes = new Uint8Array(32);
      bytes[31] = lowNibble;
      return encodeBase64url32(bytes);
    });
    expect(encodings.map((value) => value.at(-1))).toEqual([
      "A", "E", "I", "M", "Q", "U", "Y", "c",
      "g", "k", "o", "s", "w", "0", "4", "8",
    ]);
    for (const dedupeKey of encodings) {
      await expect(insertTransientAlertState({ dedupeKey })).resolves.toHaveLength(36);
    }
  });

  it("rejects invalid rule, threshold, and subject-hash state", async () => {
    await expect(insertAlertState({ ruleId: "arbitrary_rule" })).rejects.toThrow();
    await expect(insertAlertState({ criticalThreshold: 5 })).rejects.toThrow();
    await expect(
      insertAlertState({ breachSeverity: null, consecutiveBreaches: 0 }),
    ).rejects.toThrow();
    await expect(insertAlertState({ observedValue: 12.5 })).rejects.toThrow();
    await expect(insertAlertState({ provider: "apple" })).rejects.toThrow();
    await expect(insertAlertState({ reason: "rotation_failed" })).rejects.toThrow();
    await expect(insertAlertState({ surface: "archive" })).rejects.toThrow();
    await expect(
      insertAlertState({ dedupeKey: nonCanonical43() }),
    ).rejects.toThrow();
    await expect(insertAlertState({ cooldownUntil: NOW })).rejects.toThrow();
    await expect(
      insertAlertState({ breachSeverity: "warning", consecutiveBreaches: 2 }),
    ).rejects.toThrow();
    await expect(insertAlertState({ subjectRef: opaque43() })).rejects.toThrow();
    await expect(
      insertAlertState({ hashVersion: 1, subjectRef: "short" }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        hashVersion: 1,
        ruleId: "pgid.restricted.sensitive_denied.v1",
        subjectRef: nonCanonical43(),
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        hashVersion: 1,
        ruleId: "pgid.restricted.sensitive_denied.v1",
        subjectRef: opaque43(),
      }),
    ).resolves.toHaveLength(36);
    await expect(
      insertAlertState({ ruleId: "pgid.restricted.sensitive_denied.v1" }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({ queueName: "alert_deliveries_dlq" }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        criticalThreshold: null,
        metricName: "depth",
        queueName: "alert_deliveries",
        ruleId: "pgid.queue.dlq_approximate.v1",
        sourceKind: "queue_approximate",
        warningThreshold: 1,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        criticalThreshold: null,
        hashVersion: 1,
        metricName: "depth",
        queueName: "alert_deliveries_dlq",
        ruleId: "pgid.queue.dlq_approximate.v1",
        sourceKind: "queue_approximate",
        subjectRef: opaque43(),
        warningThreshold: 1,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        metricKind: "ratio",
        metricName: "ratio",
        metricUnit: "basis_points",
        minimumSampleCount: 10,
        minimumNumeratorCount: 2,
        observedDenominator: 20,
        observedNumerator: 5,
        observedValue: 2500,
        ruleId: "pgid.registration.challenge_unavailable.v1",
      }),
    ).resolves.toHaveLength(36);
    await expect(
      insertAlertState({
        metricKind: "ratio",
        metricName: "ratio",
        metricUnit: "basis_points",
        minimumSampleCount: 30,
        minimumNumeratorCount: 2,
        observedDenominator: 20,
        observedNumerator: 5,
        observedValue: 2500,
        ruleId: "pgid.registration.challenge_unavailable.v1",
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        criticalThreshold: null,
        metricName: "depth",
        queueName: "alert_deliveries_dlq",
        ruleId: "pgid.queue.dlq_approximate.v1",
        sourceKind: "queue_approximate",
        warningThreshold: 1,
      }),
    ).resolves.toHaveLength(36);
    await expect(
      insertAlertState({
        criticalThreshold: null,
        metricName: "depth",
        queueName: "alert_deliveries_dlq",
        ruleId: "pgid.queue.dlq_approximate.v1",
        sourceKind: "d1_exact",
        warningThreshold: 1,
      }),
    ).rejects.toThrow();
  });

  it("deduplicates semantic global, subject, and Queue state identities", async () => {
    await insertAlertState();
    await expect(insertAlertState()).rejects.toThrow();

    const subjectRef = opaque43();
    await insertAlertState({
      hashVersion: 1,
      ruleId: "pgid.admin.directory_volume.v1",
      subjectRef,
    });
    await expect(
      insertAlertState({
        hashVersion: 1,
        ruleId: "pgid.admin.directory_volume.v1",
        subjectRef,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        hashVersion: 1,
        ruleId: "pgid.admin.directory_volume.v1",
        subjectRef: opaque43(),
      }),
    ).resolves.toHaveLength(36);

    const queueState = (queueName: string) =>
      insertAlertState({
        criticalThreshold: null,
        metricName: "depth",
        queueName,
        ruleId: "pgid.queue.dlq_approximate.v1",
        sourceKind: "queue_approximate",
        warningThreshold: 1,
      });
    await queueState("audit_archive_dlq");
    await expect(queueState("audit_archive_dlq")).rejects.toThrow();
    await expect(queueState("alert_deliveries_dlq")).resolves.toHaveLength(36);
  });

  it("preserves lossless primary, ratio, and two-component evidence", async () => {
    await expect(
      insertTransientAlertState({
        criticalThreshold: null,
        warningThreshold: 10,
      }),
    ).resolves.toHaveLength(36);
    await expect(
      insertTransientAlertState({
        criticalThreshold: 10,
        warningThreshold: null,
      }),
    ).resolves.toHaveLength(36);
    await expect(
      insertAlertState({ criticalThreshold: null, warningThreshold: null }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({ criticalThreshold: 40, warningThreshold: 13 }),
    ).rejects.toThrow();
    await expect(
      insertTransientAlertState({
        breachSeverity: "warning",
        consecutiveBreaches: 1,
      }),
    ).resolves.toHaveLength(36);
    const pendingCriticalStateId = await insertAlertState({ observedValue: 40 });
    await insertSecurityAlert(pendingCriticalStateId, 1, {
      observedValue: 40,
      threshold: 10,
    });
    const pendingCriticalEvaluatedAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET breach_severity = 'critical', consecutive_breaches = 1,
                revision = revision + 1, last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(
          pendingCriticalEvaluatedAt,
          pendingCriticalEvaluatedAt,
          pendingCriticalStateId,
        )
        .run(),
    ).resolves.toBeDefined();

    const adminRule = "pgid.admin.sensitive_activity.v1";
    const crossMetricStateId = await insertAlertState({
      criticalThreshold: null,
      hashVersion: 1,
      metricName: "successes",
      observedValue: 1,
      ruleId: adminRule,
      subjectRef: opaque43(),
      warningThreshold: 1,
    });
    await insertSecurityAlert(crossMetricStateId, 1, {
      metricName: "successes",
      observedValue: 1,
      ruleId: adminRule,
      threshold: 1,
    });
    const crossMetricEvaluatedAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET metric_name = 'count', observed_value = 3,
                warning_threshold = NULL, critical_threshold = 3,
                breach_severity = 'critical', consecutive_breaches = 1,
                revision = revision + 1, last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(
          crossMetricEvaluatedAt,
          crossMetricEvaluatedAt,
          crossMetricStateId,
        )
        .run(),
    ).resolves.toBeDefined();

    const activeCriticalRule = "pgid.registration.rate_limited.v1";
    const activeCriticalStateId = await insertAlertState({
      observedValue: 40,
      ruleId: activeCriticalRule,
    });
    await expect(
      insertSecurityAlert(activeCriticalStateId, 1, {
        observedValue: 40,
        ruleId: activeCriticalRule,
        severity: "critical",
        threshold: 40,
      }),
    ).resolves.toHaveLength(36);
    await expect(
      insertAlertState({ breachSeverity: "warning", consecutiveBreaches: 0 }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({ breachSeverity: null, consecutiveBreaches: 1 }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        breachSeverity: "warning",
        consecutiveBreaches: 1,
        currentSeverity: "warning",
        generation: 1,
        lastNotificationScheduledAt: NOW,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        breachSeverity: "critical",
        consecutiveBreaches: 1,
        currentSeverity: "critical",
        generation: 1,
        lastNotificationScheduledAt: NOW,
        observedValue: 40,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        breachSeverity: "warning",
        consecutiveBreaches: 1,
        consecutiveClears: 1,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({ currentSeverity: "warning", generation: 1 }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        cooldownUntil: NOW,
        currentSeverity: "warning",
        generation: 1,
        lastNotificationScheduledAt: NOW,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        currentSeverity: "warning",
        generation: 1,
        lastNotificationScheduledAt: "2026-07-17T10:01:00.000Z",
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({ lastNotificationScheduledAt: NOW }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({ metricKind: "ratio", metricName: "count" }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({ metricName: "known_surfaces" }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        metricName: "dead",
        ruleId: "pgid.registration.denied.v1",
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        criticalThreshold: 10,
        metricName: "missing",
        observedValue: 10,
        ruleId: "pgid.security.fanout_gap.v1",
        warningThreshold: null,
      }),
    ).resolves.toHaveLength(36);
    await expect(
      insertTransientAlertState({
        criticalThreshold: 15,
        metricKind: "consecutive",
        metricName: "consecutive_nonzero_samples",
        metricUnit: "samples",
        observedValue: 15,
        queueName: "security_events_dlq",
        ruleId: "pgid.queue.dlq_approximate.v1",
        sourceKind: "queue_approximate",
        warningThreshold: null,
      }),
    ).resolves.toHaveLength(36);
    await expect(
      insertAlertState({
        criticalThreshold: 15,
        metricKind: "consecutive",
        metricName: "nonzero_minutes",
        metricUnit: "samples",
        observedValue: 15,
        queueName: "security_events_dlq",
        ruleId: "pgid.queue.dlq_approximate.v1",
        sourceKind: "queue_approximate",
        warningThreshold: null,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        metricKind: "ratio",
        metricName: "ratio",
        metricUnit: "basis_points",
        minimumSampleCount: 10,
        observedDenominator: 20,
        observedNumerator: 5,
        observedValue: 2500,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        metricKind: "ratio",
        metricName: "ratio",
        metricUnit: "basis_points",
        minimumNumeratorCount: 6,
        minimumSampleCount: 10,
        observedDenominator: 20,
        observedNumerator: 5,
        observedValue: 2500,
      }),
    ).rejects.toThrow();

    const ratioRule = "pgid.registration.challenge_unavailable.v1";
    const ratioStateId = await insertAlertState({
      criticalThreshold: 5000,
      metricKind: "ratio",
      metricName: "ratio",
      metricUnit: "basis_points",
      minimumNumeratorCount: 2,
      minimumSampleCount: 5,
      observedDenominator: 10,
      observedNumerator: 5,
      observedValue: 5000,
      ruleId: ratioRule,
      warningThreshold: 2000,
    });
    const ratioAlertId = await insertSecurityAlert(ratioStateId, 1, {
      metricKind: "ratio",
      metricName: "ratio",
      metricUnit: "basis_points",
      minimumNumeratorCount: 2,
      minimumSampleCount: 5,
      observedDenominator: 10,
      observedNumerator: 5,
      observedValue: 5000,
      ruleId: ratioRule,
      severity: "critical",
      threshold: 5000,
    });
    await expect(
      insertOutbox({
        alertId: ratioAlertId,
        deliveryKey: deliveryKey("7"),
        metricKind: "ratio",
        metricName: "ratio",
        metricUnit: "basis_points",
        minimumNumeratorCount: 2,
        minimumSampleCount: 5,
        observedDenominator: 10,
        observedNumerator: 5,
        observedValue: 5000,
        ruleId: ratioRule,
        severity: "critical",
        threshold: 5000,
      }),
    ).resolves.toBeTypeOf("number");
    await expect(
      insertOutbox({
        alertId: ratioAlertId,
        deliveryKey: deliveryKey("8"),
        metricKind: "ratio",
        metricName: "ratio",
        metricUnit: "basis_points",
        minimumNumeratorCount: 3,
        minimumSampleCount: 5,
        observedDenominator: 10,
        observedNumerator: 5,
        observedValue: 5000,
        ruleId: ratioRule,
        severity: "critical",
        threshold: 5000,
      }),
    ).rejects.toThrow();

    const restrictedRule = "pgid.restricted.sensitive_denied.v1";
    const restrictedSubjectRef = opaque43();
    await expect(
      insertAlertState({
        criticalThreshold: 5,
        hashVersion: 1,
        observedValue: 5,
        ruleId: restrictedRule,
        secondaryMetricName: "known_surfaces",
        subjectRef: restrictedSubjectRef,
        warningThreshold: null,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        criticalThreshold: 5,
        observedValue: 5,
        ruleId: "pgid.registration.denied.v1",
        secondaryMetricKind: "count",
        secondaryMetricName: "known_surfaces",
        secondaryMetricUnit: "events",
        secondaryObservedValue: 2,
        secondaryThreshold: 2,
        warningThreshold: null,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        criticalThreshold: 5,
        hashVersion: 1,
        observedValue: 5,
        ruleId: restrictedRule,
        secondaryMetricKind: "count",
        secondaryMetricName: "known_surfaces",
        secondaryMetricUnit: "events",
        secondaryObservedValue: 1,
        secondaryThreshold: 2,
        subjectRef: restrictedSubjectRef,
        warningThreshold: null,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        criticalThreshold: 5,
        hashVersion: 1,
        observedValue: 5,
        ruleId: restrictedRule,
        secondaryMetricKind: "count",
        secondaryMetricName: "known_surfaces",
        secondaryMetricUnit: "events",
        secondaryObservedValue: 6,
        secondaryThreshold: 2,
        subjectRef: restrictedSubjectRef,
        warningThreshold: null,
      }),
    ).rejects.toThrow();
    await expect(
      insertAlertState({
        criticalThreshold: 10,
        hashVersion: 1,
        observedValue: 10,
        ruleId: restrictedRule,
        secondaryMetricKind: "count",
        secondaryMetricName: "known_surfaces",
        secondaryMetricUnit: "events",
        secondaryObservedValue: 8,
        secondaryThreshold: 2,
        subjectRef: restrictedSubjectRef,
        warningThreshold: null,
      }),
    ).rejects.toThrow();

    const restrictedStateId = await insertAlertState({
      criticalThreshold: 5,
      hashVersion: 1,
      observedValue: 5,
      ruleId: restrictedRule,
      secondaryMetricKind: "count",
      secondaryMetricName: "known_surfaces",
      secondaryMetricUnit: "events",
      secondaryObservedValue: 2,
      secondaryThreshold: 2,
      subjectRef: restrictedSubjectRef,
      warningThreshold: null,
    });
    await expect(
      insertSecurityAlert(restrictedStateId, 1, {
        observedValue: 5,
        ruleId: restrictedRule,
        severity: "critical",
        secondaryMetricKind: "count",
        secondaryMetricName: "known_surfaces",
        secondaryMetricUnit: "events",
        secondaryObservedValue: 2,
        secondaryThreshold: 2,
        threshold: 6,
      }),
    ).rejects.toThrow();
    await expect(
      insertSecurityAlert(restrictedStateId, 1, {
        observedValue: 5,
        ruleId: restrictedRule,
        severity: "critical",
        secondaryMetricKind: "count",
        secondaryMetricName: "known_surfaces",
        secondaryMetricUnit: "events",
        secondaryObservedValue: 6,
        secondaryThreshold: 2,
        threshold: 5,
      }),
    ).rejects.toThrow();
    const restrictedAlertId = await insertSecurityAlert(restrictedStateId, 1, {
      observedValue: 5,
      ruleId: restrictedRule,
      severity: "critical",
      secondaryMetricKind: "count",
      secondaryMetricName: "known_surfaces",
      secondaryMetricUnit: "events",
      secondaryObservedValue: 2,
      secondaryThreshold: 2,
      threshold: 5,
    });
    await expect(
      insertOutbox({
        alertId: restrictedAlertId,
        deliveryKey: deliveryKey("9"),
        hashVersion: 1,
        observedValue: 5,
        ruleId: restrictedRule,
        secondaryMetricKind: "count",
        secondaryMetricName: "known_surfaces",
        secondaryMetricUnit: "events",
        secondaryObservedValue: 2,
        secondaryThreshold: 2,
        severity: "critical",
        subjectRef: restrictedSubjectRef,
        threshold: 6,
      }),
    ).rejects.toThrow();
    const restrictedDeliveryKey = deliveryKey("4");
    await insertOutbox({
      alertId: restrictedAlertId,
      deliveryKey: restrictedDeliveryKey,
      hashVersion: 1,
      observedValue: 5,
      ruleId: restrictedRule,
      secondaryMetricKind: "count",
      secondaryMetricName: "known_surfaces",
      secondaryMetricUnit: "events",
      secondaryObservedValue: 2,
      secondaryThreshold: 2,
      severity: "critical",
      subjectRef: restrictedSubjectRef,
      threshold: 5,
    });
    const restrictedPayload = await env.PG72_ID_DB.prepare(
      "SELECT payload_json FROM alert_outbox WHERE delivery_key = ?",
    )
      .bind(restrictedDeliveryKey)
      .first<{ payload_json: string }>();
    expect(JSON.parse(restrictedPayload!.payload_json)).toMatchObject({
      metricName: "count",
      minimumNumeratorCount: null,
      secondaryMetricKind: "count",
      secondaryMetricName: "known_surfaces",
      secondaryMetricUnit: "events",
      secondaryObservedValue: 2,
      secondaryThreshold: 2,
    });
    await expect(
      insertOutbox({
        alertId: restrictedAlertId,
        deliveryKey: deliveryKey("5"),
        hashVersion: 1,
        observedValue: 5,
        ruleId: restrictedRule,
        secondaryMetricKind: "count",
        secondaryMetricName: "known_surfaces",
        secondaryMetricUnit: "events",
        secondaryObservedValue: 3,
        secondaryThreshold: 2,
        severity: "critical",
        subjectRef: restrictedSubjectRef,
        threshold: 5,
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId: restrictedAlertId,
        deliveryKey: deliveryKey("6"),
        hashVersion: 1,
        observedValue: 5,
        ruleId: restrictedRule,
        secondaryMetricKind: "count",
        secondaryMetricName: "known_surfaces",
        secondaryMetricUnit: "events",
        secondaryObservedValue: 6,
        secondaryThreshold: 2,
        severity: "critical",
        subjectRef: restrictedSubjectRef,
        threshold: 5,
      }),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE alert_outbox SET secondary_observed_value = 3 WHERE delivery_key = ?",
      )
        .bind(restrictedDeliveryKey)
        .run(),
    ).rejects.toThrow();
    const oauthRule = "pgid.oauth.client_report.v1";
    const oauthSubjectRef = opaque43();
    const oauthStateId = await insertAlertState({
      criticalThreshold: 3,
      hashVersion: 1,
      metricName: "high_risk_count",
      observedValue: 3,
      ruleId: oauthRule,
      secondaryMetricKind: "count",
      secondaryMetricName: "distinct_reporters",
      secondaryMetricUnit: "events",
      secondaryObservedValue: 2,
      secondaryThreshold: 2,
      subjectRef: oauthSubjectRef,
      warningThreshold: null,
    });
    const oauthAlertId = await insertSecurityAlert(oauthStateId, 1, {
      metricName: "high_risk_count",
      observedValue: 3,
      ruleId: oauthRule,
      secondaryMetricKind: "count",
      secondaryMetricName: "distinct_reporters",
      secondaryMetricUnit: "events",
      secondaryObservedValue: 2,
      secondaryThreshold: 2,
      severity: "critical",
      threshold: 3,
    });
    await expect(
      insertOutbox({
        alertId: oauthAlertId,
        deliveryKey: deliveryKey("6"),
        hashVersion: 1,
        metricName: "high_risk_count",
        observedValue: 3,
        ruleId: oauthRule,
        secondaryMetricKind: "count",
        secondaryMetricName: "distinct_reporters",
        secondaryMetricUnit: "events",
        secondaryObservedValue: 2,
        secondaryThreshold: 2,
        severity: "critical",
        subjectRef: oauthSubjectRef,
        threshold: 3,
      }),
    ).resolves.toBeTypeOf("number");
  });

  it("permits only one unresolved incident per dedupe state", async () => {
    const stateId = await insertAlertState();
    const firstAlertId = await insertSecurityAlert(stateId, 1);
    const refreshedAt = nextEvaluationTime();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET window_seconds = 300, observed_value = 30,
              warning_threshold = 20, revision = revision + 1,
              last_evaluated_at = ?, updated_at = ?
        WHERE id = ?`,
    )
      .bind(refreshedAt, refreshedAt, stateId)
      .run();
    await env.PG72_ID_DB.prepare(
      `UPDATE security_alert
          SET window_seconds = 300, metric_name = 'count', metric_kind = 'count',
              metric_unit = 'events', observed_value = 30,
              observed_numerator = NULL, observed_denominator = NULL,
              minimum_sample_count = 0, minimum_numerator_count = NULL,
              threshold = 20, updated_at = ?
        WHERE id = ?`,
    )
      .bind(NOW, firstAlertId)
      .run();
    const incidentEscalationCandidateAt = nextEvaluationTime();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET observed_value = 40, breach_severity = 'critical',
              consecutive_breaches = 1, revision = revision + 1,
              last_evaluated_at = ?, updated_at = ?
        WHERE id = ?`,
    )
      .bind(
        incidentEscalationCandidateAt,
        incidentEscalationCandidateAt,
        stateId,
      )
      .run();
    const escalatedAt = nextEvaluationTime();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET current_severity = 'critical', consecutive_breaches = 0,
              breach_severity = NULL, revision = revision + 1,
              last_breached_at = ?,
              last_evaluated_at = ?, updated_at = ?
        WHERE id = ?`,
    )
      .bind(NOW, escalatedAt, escalatedAt, stateId)
      .run();
    await env.PG72_ID_DB.prepare(
      `UPDATE security_alert
          SET severity = 'critical', observed_value = 40, threshold = 40,
              updated_at = ?
        WHERE id = ?`,
    )
      .bind(NOW, firstAlertId)
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE security_alert SET severity = 'warning', updated_at = ? WHERE id = ?",
      )
        .bind(NOW, firstAlertId)
        .run(),
    ).rejects.toThrow();
    await expect(insertSecurityAlert(stateId, 2)).rejects.toThrow();

    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE security_alert
            SET status = 'acknowledged', acknowledged_at = ?,
                acknowledged_by_ref = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, opaque43(), NOW, firstAlertId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE security_alert
            SET status = 'resolved', resolved_at = ?,
                resolved_by_ref = ?, resolution_code = 'operator_resolved',
                updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, opaque43(), NOW, firstAlertId)
        .run(),
    ).rejects.toThrow();

    const operatorRef = opaque43();
    await env.PG72_ID_DB.prepare(
      `UPDATE security_alert
          SET status = 'acknowledged', acknowledged_at = ?,
              acknowledged_by_ref = ?, acknowledged_by_hash_version = 1,
              updated_at = ?
        WHERE id = ?`,
    )
      .bind(NOW, operatorRef, NOW, firstAlertId)
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE security_alert SET acknowledged_by_ref = ? WHERE id = ?",
      )
        .bind(opaque43(), firstAlertId)
        .run(),
    ).rejects.toThrow();

    await clearAlertState(stateId);
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE security_alert
            SET status = 'resolved', resolved_at = ?, resolved_by_ref = ?,
                resolved_by_hash_version = 1, resolution_code = 'healthy',
                updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, opaque43(), NOW, firstAlertId)
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE security_alert
          SET status = 'resolved', resolved_at = ?, resolution_code = 'healthy',
              updated_at = ?
        WHERE id = ?`,
    )
      .bind(NOW, NOW, firstAlertId)
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE security_alert
            SET status = 'open', resolved_at = NULL, resolution_code = NULL,
                updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, firstAlertId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE security_alert
            SET observed_value = 4000, observed_numerator = 4, updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, firstAlertId)
        .run(),
    ).rejects.toThrow();
    await expireAlertCooldown(stateId);
    const resetAt = nextEvaluationTime();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET window_seconds = 900, observed_value = 12,
              warning_threshold = 10, critical_threshold = 40,
              revision = revision + 1, last_evaluated_at = ?, updated_at = ?
        WHERE id = ?`,
    )
      .bind(resetAt, resetAt, stateId)
      .run();
    await expect(insertSecurityAlert(stateId, 2)).resolves.toHaveLength(36);
    await expect(insertSecurityAlert(stateId, 2)).rejects.toThrow();
  });

  it("enforces lifecycle CAS, streaks, and ordered fanout resolution", async () => {
    const stateId = await insertAlertState();
    await expect(
      insertSecurityAlert(stateId, 1, {
        acknowledgedAt: NOW,
        acknowledgedByHashVersion: 1,
        acknowledgedByRef: opaque43(),
        status: "acknowledged",
      }),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET revision = 1, last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, nextEvaluationTime(), stateId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET revision = 1, last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind("2026-07-17T09:59:59.000Z", nextEvaluationTime(), stateId)
        .run(),
    ).rejects.toThrow();
    const inventedCooldownAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET cooldown_until = '2026-07-17T10:30:00.000Z', revision = 1,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(inventedCooldownAt, inventedCooldownAt, stateId)
        .run(),
    ).rejects.toThrow();
    const candidateFreeOpenAt = nextEvaluationTime();
    await expect(
      insertSecurityAlert(stateId, 1, {
        resolutionCode: "operator_resolved",
        resolvedAt: NOW,
        resolvedByHashVersion: 1,
        resolvedByRef: opaque43(),
        status: "resolved",
      }),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET current_severity = 'warning', generation = 1, revision = 1,
                last_notification_scheduled_at = ?, last_breached_at = ?,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, NOW, candidateFreeOpenAt, candidateFreeOpenAt, stateId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE alert_state SET revision = 2 WHERE id = ?",
      )
        .bind(stateId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE alert_state SET generation = 2, revision = 1 WHERE id = ?",
      )
        .bind(stateId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET breach_severity = 'warning', consecutive_breaches = 2,
                revision = 1
          WHERE id = ?`,
      )
        .bind(stateId)
        .run(),
    ).rejects.toThrow();

    const lifecycleAlertId = await insertSecurityAlert(stateId);
    for (const acknowledgedAt of [
      "2026-07-17T09:59:59.000Z",
      "2026-07-17T10:01:00.000Z",
    ]) {
      await expect(
        env.PG72_ID_DB.prepare(
          `UPDATE security_alert
              SET status = 'acknowledged', acknowledged_at = ?,
                  acknowledged_by_ref = ?, acknowledged_by_hash_version = 1,
                  updated_at = ?
            WHERE id = ?`,
        )
          .bind(acknowledgedAt, opaque43(), NOW, lifecycleAlertId)
          .run(),
      ).rejects.toThrow();
    }
    for (const resolvedAt of [
      "2026-07-17T09:59:59.000Z",
      "2026-07-17T10:01:00.000Z",
    ]) {
      await expect(
        env.PG72_ID_DB.prepare(
          `UPDATE security_alert
              SET status = 'resolved', resolved_at = ?, resolved_by_ref = ?,
                  resolved_by_hash_version = 1,
                  resolution_code = 'operator_resolved', updated_at = ?
            WHERE id = ?`,
        )
          .bind(resolvedAt, opaque43(), NOW, lifecycleAlertId)
          .run(),
      ).rejects.toThrow();
    }
    const jumpedClearAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET consecutive_clears = 4, revision = revision + 1,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(jumpedClearAt, jumpedClearAt, stateId)
        .run(),
    ).rejects.toThrow();
    const prematureResolutionAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET current_severity = 'none', revision = revision + 1,
                last_notification_scheduled_at = NULL, last_cleared_at = ?,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(
          NOW,
          prematureResolutionAt,
          prematureResolutionAt,
          stateId,
        )
        .run(),
    ).rejects.toThrow();
    const candidateFreeEscalationAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET current_severity = 'critical', observed_value = 40,
                revision = revision + 1, last_breached_at = ?,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(
          NOW,
          candidateFreeEscalationAt,
          candidateFreeEscalationAt,
          stateId,
        )
        .run(),
    ).rejects.toThrow();
    const criticalCandidateAt = nextEvaluationTime();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET observed_value = 40, breach_severity = 'critical',
              consecutive_breaches = 1, revision = revision + 1,
              last_evaluated_at = ?, updated_at = ?
        WHERE id = ?`,
    )
      .bind(criticalCandidateAt, criticalCandidateAt, stateId)
      .run();
    const generationJumpAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET current_severity = 'critical', generation = generation + 1,
                consecutive_breaches = 0, breach_severity = NULL,
                revision = revision + 1, last_breached_at = ?,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, generationJumpAt, generationJumpAt, stateId)
        .run(),
    ).rejects.toThrow();
    const confirmedCriticalAt = nextEvaluationTime();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET current_severity = 'critical', consecutive_breaches = 0,
              breach_severity = NULL, revision = revision + 1,
              last_breached_at = ?, last_evaluated_at = ?, updated_at = ?
        WHERE id = ?`,
    )
      .bind(NOW, confirmedCriticalAt, confirmedCriticalAt, stateId)
      .run();

    const cooldownRule = "pgid.registration.restricted_created.v1";
    const cooldownStateId = await insertAlertState({ ruleId: cooldownRule });
    await insertSecurityAlert(cooldownStateId, 1, { ruleId: cooldownRule });
    await recordFourClearSamples(cooldownStateId);
    const missingCooldownClearAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET current_severity = 'none', consecutive_clears = 0,
                revision = revision + 1, last_notification_scheduled_at = NULL,
                last_cleared_at = ?, last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(
          NOW,
          missingCooldownClearAt,
          missingCooldownClearAt,
          cooldownStateId,
        )
        .run(),
    ).rejects.toThrow();
    const invalidCooldownClearAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET current_severity = 'none', consecutive_clears = 0,
                revision = revision + 1, last_notification_scheduled_at = NULL,
                cooldown_until = '2026-07-17T12:00:00.000Z',
                last_cleared_at = ?, last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(
          NOW,
          invalidCooldownClearAt,
          invalidCooldownClearAt,
          cooldownStateId,
        )
        .run(),
    ).rejects.toThrow();

    const runtimeStateId = await insertAlertState({
      criticalThreshold: 1,
      metricKind: "boolean",
      metricName: "evaluator_missing",
      metricUnit: "state",
      observedValue: 1,
      ruleId: "pgid.alert.runtime_health.v1",
      warningThreshold: null,
    });
    const immediateCriticalAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET current_severity = 'critical', generation = 1, revision = 1,
                breach_severity = NULL, consecutive_breaches = 0,
                last_notification_scheduled_at = ?, last_breached_at = ?,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(
          NOW,
          NOW,
          immediateCriticalAt,
          immediateCriticalAt,
          runtimeStateId,
        )
        .run(),
    ).resolves.toBeDefined();
    await expect(
      insertSecurityAlert(runtimeStateId, 1, {
        metricKind: "boolean",
        metricName: "evaluator_missing",
        metricUnit: "state",
        observedValue: 1,
        ruleId: "pgid.alert.runtime_health.v1",
        severity: "critical",
        threshold: 1,
      }),
    ).resolves.toHaveLength(36);

    const fanoutRule = "pgid.security.fanout_gap.v1";
    const fanoutStateId = await insertAlertState({
      criticalThreshold: 10,
      metricName: "missing",
      observedValue: 10,
      ruleId: fanoutRule,
      warningThreshold: null,
    });
    const fanoutAlertId = await insertSecurityAlert(fanoutStateId, 1, {
      metricName: "missing",
      observedValue: 10,
      ruleId: fanoutRule,
      severity: "critical",
      threshold: 10,
    });
    const rejectedAutomaticClearAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET consecutive_clears = 1, revision = revision + 1,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(
          rejectedAutomaticClearAt,
          rejectedAutomaticClearAt,
          fanoutStateId,
        )
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE security_alert
            SET status = 'resolved', resolved_at = ?,
                resolution_code = 'healthy', updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, NOW, fanoutAlertId)
        .run(),
    ).rejects.toThrow();
    const manualClear = () => {
      const evaluatedAt = nextEvaluationTime();
      return env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET current_severity = 'none', consecutive_breaches = 0,
                breach_severity = NULL, consecutive_clears = 0,
                revision = revision + 1, last_notification_scheduled_at = NULL,
                cooldown_until = ?, last_cleared_at = ?,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(
          cooldownAfter(evaluatedAt),
          NOW,
          evaluatedAt,
          evaluatedAt,
          fanoutStateId,
        )
        .run();
    };
    await expect(manualClear()).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE security_alert
            SET status = 'resolved', resolved_at = ?, resolved_by_ref = ?,
                resolved_by_hash_version = 1,
                resolution_code = 'operator_resolved', updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, nonCanonical43(), NOW, fanoutAlertId)
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE security_alert
          SET status = 'resolved', resolved_at = ?, resolved_by_ref = ?,
              resolved_by_hash_version = 1,
              resolution_code = 'operator_resolved', updated_at = ?
        WHERE id = ?`,
    )
      .bind(NOW, opaque43(), NOW, fanoutAlertId)
      .run();
    await expect(manualClear()).resolves.toBeDefined();
    await insertSecurityAlert(fanoutStateId, 2, {
      metricName: "missing",
      observedValue: 10,
      ruleId: fanoutRule,
      severity: "critical",
      threshold: 10,
    });
    await expect(manualClear()).rejects.toThrow();
  });

  it("keeps warning cooldown closed until its exact expiry", async () => {
    const stateId = await insertAlertState();
    const alertId = await insertSecurityAlert(stateId);
    await clearAlertState(stateId);
    const cooldownUntil = await env.PG72_ID_DB.prepare(
      "SELECT cooldown_until FROM alert_state WHERE id = ?",
    )
      .bind(stateId)
      .first<string>("cooldown_until");
    expect(cooldownUntil).not.toBeNull();

    const earlyClearAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET cooldown_until = NULL, revision = revision + 1,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(earlyClearAt, earlyClearAt, stateId)
        .run(),
    ).rejects.toThrow();

    const pendingAt = nextEvaluationTime();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET breach_severity = 'warning', consecutive_breaches = 1,
              revision = revision + 1, last_evaluated_at = ?, updated_at = ?
        WHERE id = ?`,
    )
      .bind(pendingAt, pendingAt, stateId)
      .run();
    const earlyConfirmAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET current_severity = 'warning', generation = generation + 1,
                breach_severity = NULL, consecutive_breaches = 0,
                cooldown_until = NULL, last_notification_scheduled_at = ?,
                last_breached_at = ?, revision = revision + 1,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(
          earlyConfirmAt,
          earlyConfirmAt,
          earlyConfirmAt,
          earlyConfirmAt,
          stateId,
        )
        .run(),
    ).rejects.toThrow();

    evaluationTick = Math.max(
      evaluationTick,
      (Date.parse(cooldownUntil!) - Date.parse(NOW)) / 1000,
    );
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET current_severity = 'warning', generation = generation + 1,
              breach_severity = NULL, consecutive_breaches = 0,
              cooldown_until = NULL, last_notification_scheduled_at = ?,
              last_breached_at = ?, revision = revision + 1,
              last_evaluated_at = ?, updated_at = ?
        WHERE id = ?`,
    )
      .bind(
        cooldownUntil,
        cooldownUntil,
        cooldownUntil,
        cooldownUntil,
        stateId,
      )
      .run();
    await env.PG72_ID_DB.prepare(
      `UPDATE security_alert
          SET status = 'resolved', resolved_at = ?, resolution_code = 'healthy',
              updated_at = ?
        WHERE id = ?`,
    )
      .bind(NOW, NOW, alertId)
      .run();
    await expect(insertSecurityAlert(stateId, 2)).resolves.toHaveLength(36);
  });

  it("rejects acknowledgement and delivery snapshots from stale state", async () => {
    const stateId = await insertAlertState();
    const alertId = await insertSecurityAlert(stateId);
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE security_alert
            SET status = 'acknowledged', acknowledged_at = ?,
                acknowledged_by_ref = ?, acknowledged_by_hash_version = 1,
                updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, nonCanonical43(), NOW, alertId)
        .run(),
    ).rejects.toThrow();
    await clearAlertState(stateId);
    const cooldownExtensionAt = nextEvaluationTime();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET cooldown_until = '2026-07-17T12:00:00.000Z',
                revision = revision + 1, last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      )
        .bind(cooldownExtensionAt, cooldownExtensionAt, stateId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE security_alert
            SET status = 'acknowledged', acknowledged_at = ?,
                acknowledged_by_ref = ?, acknowledged_by_hash_version = 1,
                updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, opaque43(), NOW, alertId)
        .run(),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("f"),
        eventKind: "reminder",
        eventSequence: 2,
      }),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE security_alert
          SET status = 'resolved', resolved_at = ?, resolution_code = 'healthy',
              updated_at = ?
        WHERE id = ?`,
    )
      .bind(NOW, NOW, alertId)
      .run();
    await expireAlertCooldown(stateId);
    await insertSecurityAlert(stateId, 2);
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("g"),
        eventKind: "resolved",
        generation: 1,
        incidentStatus: "resolved",
      }),
    ).rejects.toThrow();
  });

  it("binds incident and delivery provenance to their exact parent state", async () => {
    const stateId = await insertAlertState();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE alert_state SET subject_ref = ?, hash_version = 1 WHERE id = ?",
      )
        .bind(opaque43(), stateId)
        .run(),
    ).rejects.toThrow();
    await expect(
      insertSecurityAlert(stateId, 1, {
        ruleId: "pgid.admin.sensitive_activity.v1",
      }),
    ).rejects.toThrow();
    await expect(
      insertSecurityAlert(stateId, 1, { sourceKind: "queue_approximate" }),
    ).rejects.toThrow();

    const alertId = await insertSecurityAlert(stateId);
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("Y"),
        observedValue: 13,
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("1"),
        hashVersion: 1,
        subjectRef: opaque43(),
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("R"),
        ruleId: "pgid.admin.sensitive_activity.v1",
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("S"),
        environment: "preview",
      }),
    ).rejects.toThrow();
  });

  it("enforces outbox event-kind/channel generations and stable idempotency", async () => {
    const stateId = await insertAlertState();
    const alertId = await insertSecurityAlert(stateId);
    const idempotencyKey = opaque43();
    const immutableDeliveryKey = deliveryKey();
    await insertOutbox({
      alertId,
      deliveryKey: immutableDeliveryKey,
      idempotencyKey,
    });
    const snapshotBefore = await env.PG72_ID_DB.prepare(
      `SELECT payload_json, payload_sha256, observed_value
         FROM alert_outbox WHERE delivery_key = ?`,
    )
      .bind(immutableDeliveryKey)
      .first<{
        observed_value: number;
        payload_json: string;
        payload_sha256: string;
      }>();
    expect(snapshotBefore).not.toBeNull();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE alert_outbox SET payload_json = '{}' WHERE delivery_key = ?",
      )
        .bind(immutableDeliveryKey)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE alert_outbox SET payload_sha256 = ? WHERE delivery_key = ?",
      )
        .bind("0".repeat(64), immutableDeliveryKey)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE alert_outbox SET observed_value = 13 WHERE delivery_key = ?",
      )
        .bind(immutableDeliveryKey)
        .run(),
    ).rejects.toThrow();
    const snapshotAfter = await env.PG72_ID_DB.prepare(
      `SELECT payload_json, payload_sha256, observed_value
         FROM alert_outbox WHERE delivery_key = ?`,
    )
      .bind(immutableDeliveryKey)
      .first();
    expect(snapshotAfter).toEqual(snapshotBefore);
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE alert_outbox SET updated_at = ? WHERE delivery_key = ?",
      )
        .bind("2026-07-17T09:59:59.000Z", immutableDeliveryKey)
        .run(),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: `pgid_ad_${nonCanonical43()}`,
        eventKind: "reminder",
        eventSequence: 9,
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("i"),
        eventKind: "reminder",
        eventSequence: 10,
        idempotencyKey: nonCanonical43(),
      }),
    ).rejects.toThrow();

    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("E"),
        eventKind: "opened",
        idempotencyKey: opaque43(),
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("F"),
        eventKind: "reminder",
        idempotencyKey: opaque43(),
      }),
    ).resolves.toBeTypeOf("number");
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("G"),
        eventKind: "reminder",
        eventSequence: 2,
        idempotencyKey,
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        channel: "webhook",
        deliveryKey: deliveryKey("V"),
        eventKind: "reminder",
        eventSequence: 3,
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId: crypto.randomUUID(),
        deliveryKey: deliveryKey("H"),
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("O"),
        generation: 2,
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("P"),
        eventKind: "resolved",
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("Q"),
        eventKind: "escalated",
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("T"),
        eventKind: "reminder",
        eventSequence: 1,
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("U"),
        eventKind: "reminder",
        eventSequence: 2,
      }),
    ).resolves.toBeTypeOf("number");
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("0"),
        eventKind: "reminder",
        eventSequence: 1_000_000_000,
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("3"),
        eventKind: "reminder",
        eventSequence: 3,
      }),
    ).resolves.toBeTypeOf("number");
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("a"),
        eventKind: "reminder",
        eventSequence: 1_000_000_001,
      }),
    ).rejects.toThrow();
    const eventEscalationCandidateAt = nextEvaluationTime();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET observed_value = 40, breach_severity = 'critical',
              consecutive_breaches = 1, revision = revision + 1,
              last_evaluated_at = ?, updated_at = ?
        WHERE id = ?`,
    )
      .bind(eventEscalationCandidateAt, eventEscalationCandidateAt, stateId)
      .run();
    const escalatedAt = nextEvaluationTime();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET current_severity = 'critical', consecutive_breaches = 0,
              breach_severity = NULL, revision = revision + 1,
              last_breached_at = ?,
              last_evaluated_at = ?, updated_at = ?
        WHERE id = ?`,
    )
      .bind(NOW, escalatedAt, escalatedAt, stateId)
      .run();
    await env.PG72_ID_DB.prepare(
      `UPDATE security_alert
          SET severity = 'critical', observed_value = 40, threshold = 40,
              updated_at = ?
        WHERE id = ?`,
    )
      .bind(NOW, alertId)
      .run();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("X"),
        eventKind: "escalated",
        observedValue: 40,
        severity: "critical",
        threshold: 40,
      }),
    ).resolves.toBeTypeOf("number");
    await clearAlertState(stateId);
    await env.PG72_ID_DB.prepare(
      `UPDATE security_alert
          SET status = 'resolved', resolved_at = ?, resolution_code = 'healthy',
              updated_at = ?
        WHERE id = ?`,
    )
      .bind(NOW, NOW, alertId)
      .run();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("2"),
        eventKind: "reminder",
        eventSequence: 4,
        incidentStatus: "resolved",
        observedValue: 40,
        severity: "critical",
        threshold: 40,
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("W"),
        eventKind: "resolved",
        incidentStatus: "resolved",
        observedValue: 40,
        severity: "critical",
        threshold: 40,
      }),
    ).resolves.toBeTypeOf("number");
  });

  it("requires paired leases and exact status-dependent outbox fields", async () => {
    const alertId = await insertSecurityAlert(await insertAlertState());
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("m"),
        eventKind: "reminder",
        eventSequence: 22,
        nextAttemptAt: "2026-07-17T09:59:59.000Z",
      }),
    ).rejects.toThrow();
    const futureDueId = await insertOutbox({
      alertId,
      deliveryKey: deliveryKey("j"),
      eventKind: "reminder",
      eventSequence: 1,
      nextAttemptAt: "2026-07-17T10:01:00.000Z",
    });
    await expect(
      claimOutbox(
        futureDueId,
        crypto.randomUUID(),
        "2026-07-17T10:02:00.000Z",
      ),
    ).rejects.toThrow();
    const expiredLeaseId = await insertOutbox({
      alertId,
      deliveryKey: deliveryKey("k"),
      eventKind: "reminder",
      eventSequence: 2,
    });
    await expect(
      claimOutbox(expiredLeaseId, crypto.randomUUID(), NOW),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("I"),
        leaseId: crypto.randomUUID(),
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("e"),
        replayCount: 1,
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("h"),
        nextAttemptAt: null,
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("J"),
        nextAttemptAt: null,
        status: "processing",
      }),
    ).rejects.toThrow();
    const processingLeaseId = crypto.randomUUID();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("K"),
        leaseExpiresAt: "2026-07-17T10:01:00.000Z",
        leaseId: processingLeaseId,
        nextAttemptAt: null,
        status: "processing",
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        attempts: 1,
        deliveryKey: deliveryKey("b"),
        lastErrorCode: "network",
        status: "retry",
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        acceptedAt: NOW,
        alertId,
        attempts: 1,
        deliveryKey: deliveryKey("c"),
        nextAttemptAt: null,
        status: "accepted",
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        attempts: 1,
        deadAt: NOW,
        deliveryKey: deliveryKey("d"),
        lastErrorCode: "network",
        nextAttemptAt: null,
        status: "dead",
      }),
    ).rejects.toThrow();
    const processingOutboxId = await insertOutbox({
      alertId,
      deliveryKey: deliveryKey("K"),
    });
    await claimOutbox(processingOutboxId, processingLeaseId);
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE alert_outbox SET lease_id = ?, updated_at = ? WHERE delivery_key = ?",
      )
        .bind(crypto.randomUUID(), NOW, deliveryKey("K"))
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_delivery_attempt
        (id, outbox_id, replay_count, attempt_number, lease_id, outcome,
         resulting_status, started_at)
       VALUES (?, ?, 0, 1, ?, 'in_flight', 'processing', ?)`,
    )
      .bind(crypto.randomUUID(), processingOutboxId, processingLeaseId, NOW)
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_delivery_attempt
            SET outcome = 'retry', resulting_status = 'retry',
                error_code = 'payload_integrity', completed_at = ?
          WHERE outbox_id = ? AND replay_count = 0 AND attempt_number = 1`,
      )
        .bind(NOW, processingOutboxId)
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_delivery_attempt
          SET outcome = 'dead', resulting_status = 'dead',
              error_code = 'payload_integrity', completed_at = ?
        WHERE outbox_id = ? AND replay_count = 0 AND attempt_number = 1`,
    )
      .bind(NOW, processingOutboxId)
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_outbox
            SET status = 'retry', next_attempt_at = ?, lease_id = NULL,
                lease_expires_at = NULL, last_error_code = 'payload_integrity',
                updated_at = ?
          WHERE delivery_key = ?`,
      )
        .bind("2026-07-17T10:01:00.000Z", NOW, deliveryKey("K"))
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_outbox
          SET status = 'dead', next_attempt_at = NULL, lease_id = NULL,
              lease_expires_at = NULL, dead_at = ?,
              last_error_code = 'payload_integrity', updated_at = ?
        WHERE delivery_key = ?`,
    )
      .bind(NOW, NOW, deliveryKey("K"))
      .run();
    const integrityDeadRow = await env.PG72_ID_DB.prepare(
      `SELECT status, replay_count, attempts, next_attempt_at, lease_id,
              lease_expires_at, accepted_at, dead_at, last_error_code,
              updated_at
         FROM alert_outbox WHERE delivery_key = ?`,
    )
      .bind(deliveryKey("K"))
      .first();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_outbox
            SET status = 'pending', replay_count = replay_count + 1,
                attempts = 0, next_attempt_at = ?, lease_id = NULL,
                lease_expires_at = NULL, accepted_at = NULL, dead_at = NULL,
                last_error_code = NULL, updated_at = ?
          WHERE delivery_key = ?`,
      )
        .bind(
          "2026-07-17T10:02:00.000Z",
          "2026-07-17T10:02:00.000Z",
          deliveryKey("K"),
        )
        .run(),
    ).rejects.toThrow();
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, replay_count, attempts, next_attempt_at, lease_id,
                lease_expires_at, accepted_at, dead_at, last_error_code,
                updated_at
           FROM alert_outbox WHERE delivery_key = ?`,
      )
        .bind(deliveryKey("K"))
        .first(),
    ).toEqual(integrityDeadRow);
    await insertOutbox({
      alertId,
      deliveryKey: deliveryKey("N"),
      eventKind: "reminder",
    });
    const acceptedLeaseId = crypto.randomUUID();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_outbox
            SET status = 'processing', next_attempt_at = NULL,
                lease_id = ?, lease_expires_at = ?, updated_at = ?
          WHERE delivery_key = ?`,
      )
        .bind(
          acceptedLeaseId,
          "2026-07-17T10:01:00.000Z",
          NOW,
          deliveryKey("N"),
        )
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_outbox
          SET status = 'processing', attempts = 1, next_attempt_at = NULL,
              lease_id = ?, lease_expires_at = ?, updated_at = ?
        WHERE delivery_key = ?`,
      )
      .bind(
        acceptedLeaseId,
        "2026-07-17T10:01:00.000Z",
        NOW,
        deliveryKey("N"),
      )
      .run();
    const acceptedOutbox = await env.PG72_ID_DB.prepare(
      "SELECT id FROM alert_outbox WHERE delivery_key = ?",
    )
      .bind(deliveryKey("N"))
      .first<{ id: number }>();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_delivery_attempt
        (id, outbox_id, replay_count, attempt_number, lease_id, outcome,
         resulting_status, started_at)
       VALUES (?, ?, 0, 1, ?, 'in_flight', 'processing', ?)`,
    )
      .bind(crypto.randomUUID(), acceptedOutbox!.id, acceptedLeaseId, NOW)
      .run();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_delivery_attempt
          SET outcome = 'accepted', resulting_status = 'accepted', completed_at = ?
        WHERE outbox_id = ? AND replay_count = 0 AND attempt_number = 1`,
    )
      .bind(NOW, acceptedOutbox!.id)
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_outbox
            SET status = 'accepted', lease_id = NULL, lease_expires_at = NULL,
                accepted_at = ?, updated_at = ?
          WHERE delivery_key = ?`,
      )
        .bind("2026-07-17T09:59:59.000Z", NOW, deliveryKey("N"))
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_outbox
          SET status = 'accepted', lease_id = NULL, lease_expires_at = NULL,
              accepted_at = ?, updated_at = ?
        WHERE delivery_key = ?`,
    )
      .bind(NOW, NOW, deliveryKey("N"))
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_outbox
            SET status = 'processing', attempts = 2, lease_id = ?,
                lease_expires_at = ?, accepted_at = NULL, updated_at = ?
          WHERE delivery_key = ?`,
      )
        .bind(
          crypto.randomUUID(),
          "2026-07-17T10:02:00.000Z",
          NOW,
          deliveryKey("N"),
        )
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_outbox
            SET status = 'pending', replay_count = 1, attempts = 0,
                next_attempt_at = ?, accepted_at = NULL, updated_at = ?
          WHERE delivery_key = ?`,
      )
        .bind("2026-07-17T09:59:59.000Z", NOW, deliveryKey("N"))
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_outbox
            SET status = 'pending', attempts = 0, next_attempt_at = ?,
                accepted_at = NULL, updated_at = ?
          WHERE delivery_key = ?`,
      )
        .bind(NOW, NOW, deliveryKey("N"))
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_outbox
          SET status = 'pending', replay_count = 1, attempts = 0,
              next_attempt_at = ?, accepted_at = NULL, updated_at = ?
        WHERE delivery_key = ?`,
    )
      .bind(NOW, NOW, deliveryKey("N"))
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE alert_outbox SET replay_count = 0 WHERE delivery_key = ?",
      )
        .bind(deliveryKey("N"))
        .run(),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        attempts: 1,
        deliveryKey: deliveryKey("Z"),
        eventKind: "reminder",
        eventSequence: 2,
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: deliveryKey("L"),
        eventKind: "reminder",
        eventSequence: 3,
        lastErrorCode: "raw provider error body",
        status: "retry",
      }),
    ).rejects.toThrow();
    await expect(
      insertOutbox({
        alertId,
        deliveryKey: "wrong-prefix".padEnd(51, "A"),
        eventKind: "reminder",
        eventSequence: 4,
      }),
    ).rejects.toThrow();
  });

  it("enforces unique attempt tuples, bounded outcomes, and parent foreign keys", async () => {
    const alertId = await insertSecurityAlert(await insertAlertState());
    const activeLeaseId = crypto.randomUUID();
    const outboxId = await insertOutbox({
      alertId,
      deliveryKey: deliveryKey("M"),
    });
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_delivery_attempt
          (id, outbox_id, replay_count, attempt_number, lease_id, outcome,
           resulting_status, started_at)
         VALUES (?, ?, 0, 1, ?, 'in_flight', 'processing', ?)`,
      )
        .bind(crypto.randomUUID(), outboxId, activeLeaseId, NOW)
        .run(),
    ).rejects.toThrow();
    await claimOutbox(outboxId, activeLeaseId);
    const insertAttempt = (
      attemptNumber: number,
      attemptLeaseId: string,
      outbox = outboxId,
      replayCount = 0,
    ) =>
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_delivery_attempt
          (id, outbox_id, replay_count, attempt_number, lease_id, outcome,
           resulting_status, started_at)
         VALUES (?, ?, ?, ?, ?, 'in_flight', 'processing', ?)`,
      )
        .bind(
          crypto.randomUUID(),
          outbox,
          replayCount,
          attemptNumber,
          attemptLeaseId,
          NOW,
        )
        .run();

    await expect(insertAttempt(1, crypto.randomUUID())).rejects.toThrow();
    await expect(insertAttempt(1, activeLeaseId, outboxId, 1)).rejects.toThrow();
    await expect(insertAttempt(2, activeLeaseId)).rejects.toThrow();
    await expect(
      insertAttempt(1, activeLeaseId, 9_999_999),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_delivery_attempt
          (id, outbox_id, replay_count, attempt_number, lease_id, outcome,
           resulting_status, started_at)
         VALUES (?, ?, 0, 1, ?, 'in_flight', 'processing', ?)`,
      )
        .bind(
          crypto.randomUUID(),
          outboxId,
          activeLeaseId,
          "2026-07-17T10:01:00.000Z",
        )
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_delivery_attempt
          (id, outbox_id, replay_count, attempt_number, lease_id, outcome,
           resulting_status, started_at)
         VALUES (?, ?, 0, 1, ?, 'in_flight', 'processing', ?)`,
      )
        .bind(
          crypto.randomUUID(),
          outboxId,
          activeLeaseId,
          "2026-07-17T09:59:59.000Z",
        )
        .run(),
    ).rejects.toThrow();
    await insertAttempt(1, activeLeaseId);
    await expect(insertAttempt(1, crypto.randomUUID())).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_delivery_attempt
          (id, outbox_id, replay_count, attempt_number, lease_id, outcome,
           resulting_status, error_code, started_at, completed_at)
         VALUES (?, ?, 0, 2, ?, 'retry', 'retry', NULL, ?, ?)`,
      )
        .bind(crypto.randomUUID(), outboxId, crypto.randomUUID(), NOW, NOW)
        .run(),
    ).rejects.toThrow();

    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_delivery_attempt
            SET outcome = 'retry', resulting_status = 'retry',
                error_code = 'network', completed_at = ?
          WHERE outbox_id = ? AND replay_count = 0 AND attempt_number = 1`,
      )
        .bind(NOW, outboxId)
        .run(),
    ).resolves.toBeDefined();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_delivery_attempt SET error_code = 'timeout'
          WHERE outbox_id = ? AND replay_count = 0 AND attempt_number = 1`,
      )
        .bind(outboxId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_outbox
            SET status = 'dead', lease_id = NULL, lease_expires_at = NULL,
                dead_at = ?, last_error_code = 'network', updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, NOW, outboxId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_outbox
            SET status = 'retry', next_attempt_at = ?, lease_id = NULL,
                lease_expires_at = NULL, last_error_code = 'timeout',
                updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, NOW, outboxId)
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_outbox
          SET status = 'retry', next_attempt_at = ?, lease_id = NULL,
              lease_expires_at = NULL, last_error_code = 'network', updated_at = ?
        WHERE id = ?`,
    )
      .bind(
        "2026-07-17T10:02:00.000Z",
        "2026-07-17T10:01:00.000Z",
        outboxId,
      )
      .run();
  });

  it("requires terminal attempt evidence before delivery completion", async () => {
    const alertId = await insertSecurityAlert(await insertAlertState());
    const leaseId = crypto.randomUUID();
    const outboxId = await insertOutbox({
      alertId,
      deliveryKey: deliveryKey("3"),
    });
    await claimOutbox(outboxId, leaseId);

    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_outbox
            SET status = 'retry', next_attempt_at = ?, lease_id = NULL,
                lease_expires_at = NULL, last_error_code = 'lease_expired',
                updated_at = ?
          WHERE id = ?`,
      )
        .bind(NOW, NOW, outboxId)
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_delivery_attempt
        (id, outbox_id, replay_count, attempt_number, lease_id, outcome,
         resulting_status, started_at)
       VALUES (?, ?, 0, 1, ?, 'in_flight', 'processing', ?)`,
    )
      .bind(crypto.randomUUID(), outboxId, leaseId, NOW)
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_delivery_attempt
            SET outcome = 'accepted', resulting_status = 'accepted',
                completed_at = '2026-07-17T10:02:00.000Z'
          WHERE outbox_id = ? AND replay_count = 0 AND attempt_number = 1`,
      )
        .bind(outboxId)
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_delivery_attempt
          SET outcome = 'lease_expired', resulting_status = 'retry',
              error_code = 'lease_expired', completed_at = ?
        WHERE outbox_id = ? AND replay_count = 0 AND attempt_number = 1`,
      )
      .bind("2026-07-17T10:01:00.000Z", outboxId)
      .run();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_outbox
          SET status = 'retry', next_attempt_at = ?, lease_id = NULL,
              lease_expires_at = NULL, last_error_code = 'lease_expired',
              updated_at = ?
        WHERE id = ?`,
    )
      .bind(
        "2026-07-17T10:02:00.000Z",
        "2026-07-17T10:01:00.000Z",
        outboxId,
      )
      .run();
  });

  it("bounds runtime clocks, integer samples, and lease ownership", async () => {
    for (const [column, extraColumns, extraValues] of [
      ["last_started_at", "", ""],
      ["last_success_at", "", ""],
      ["last_error_at", ", last_error_code", ", 'evaluator_failed'"],
    ] as const) {
      await expect(
        env.PG72_ID_DB.prepare(
          `INSERT INTO alert_runtime_status
            (component, ${column}${extraColumns}, updated_at)
           VALUES ('evaluator', ?${extraValues}, ?)`,
        )
          .bind("2026-07-17T10:00:01.000Z", NOW)
          .run(),
      ).rejects.toThrow();
    }
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, last_success_at, watermark_at, updated_at)
         VALUES ('evaluator', ?, '2026-07-17T10:00:01.000Z', ?)`,
      )
        .bind(NOW, NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, status, metric_sampled_at, backlog_count, backlog_bytes,
           oldest_message_age_seconds, nonzero_since_at,
           consecutive_nonzero_samples, updated_at)
         VALUES ('alert_queue', 'degraded', ?, 1.5, 10, 5, ?, 1, ?)`,
      )
        .bind(NOW, NOW, NOW)
        .run(),
    ).rejects.toThrow();

    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status (component, updated_at)
         VALUES ('evaluator', ?)`,
      ).bind(NOW),
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status (component, updated_at)
         VALUES ('delivery', ?)`,
      ).bind(NOW),
    ]);
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET last_started_at = '2026-07-17T10:01:00.000Z', revision = 1,
                updated_at = '2026-07-17T10:00:30.000Z'
          WHERE component = 'evaluator'`,
      ).run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET last_success_at = '2026-07-17T09:59:00.000Z', revision = 1,
                updated_at = '2026-07-17T10:00:30.000Z'
          WHERE component = 'evaluator'`,
      ).run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET last_started_at = '2026-07-17T10:00:20.000Z',
                last_success_at = '2026-07-17T10:00:10.000Z', revision = 1,
                updated_at = '2026-07-17T10:00:30.000Z'
          WHERE component = 'evaluator'`,
      ).run(),
    ).rejects.toThrow();

    const firstLease = crypto.randomUUID();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET generation = 1, revision = 1, lease_id = ?,
                lease_expires_at = '2026-07-17T09:59:00.000Z',
                updated_at = '2026-07-17T10:00:01.000Z'
          WHERE component = 'delivery'`,
      )
        .bind(firstLease)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET generation = 1, revision = 1, lease_id = ?,
                lease_expires_at = '2026-07-17T10:05:02.000Z',
                updated_at = '2026-07-17T10:00:01.000Z'
          WHERE component = 'delivery'`,
      )
        .bind(firstLease)
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET generation = 1, revision = 1, lease_id = ?,
              lease_expires_at = '2026-07-17T10:05:01.000Z',
              updated_at = '2026-07-17T10:00:01.000Z'
        WHERE component = 'delivery'`,
    )
      .bind(firstLease)
      .run();

    const secondLease = crypto.randomUUID();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET generation = 2, revision = 2, lease_id = ?,
                lease_expires_at = '2026-07-17T10:05:02.000Z',
                updated_at = '2026-07-17T10:00:02.000Z'
          WHERE component = 'delivery'`,
      )
        .bind(secondLease)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET revision = 2, lease_expires_at = '2026-07-17T10:04:00.000Z',
                updated_at = '2026-07-17T10:01:00.000Z'
          WHERE component = 'delivery'`,
      ).run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET revision = 2, lease_expires_at = '2026-07-17T10:06:00.000Z',
              updated_at = '2026-07-17T10:01:00.000Z'
        WHERE component = 'delivery'`,
    ).run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET revision = 3, lease_id = NULL, lease_expires_at = NULL,
                updated_at = '2026-07-17T10:06:00.000Z'
          WHERE component = 'delivery'`,
      ).run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET revision = 3, lease_id = NULL, lease_expires_at = NULL,
              updated_at = '2026-07-17T10:02:00.000Z'
        WHERE component = 'delivery'`,
    ).run();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET generation = 2, revision = 4, lease_id = ?,
              lease_expires_at = '2026-07-17T10:07:01.000Z',
              updated_at = '2026-07-17T10:02:01.000Z'
        WHERE component = 'delivery'`,
    )
      .bind(secondLease)
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET generation = 3, revision = 5, lease_id = ?,
                lease_expires_at = '2026-07-17T10:12:00.000Z',
                updated_at = '2026-07-17T10:07:00.000Z'
          WHERE component = 'delivery'`,
      )
        .bind(crypto.randomUUID())
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET generation = 3, revision = 5, lease_id = ?,
              lease_expires_at = '2026-07-17T10:12:01.000Z',
              updated_at = '2026-07-17T10:07:01.000Z'
        WHERE component = 'delivery'`,
    )
      .bind(crypto.randomUUID())
      .run();
  });

  it("preserves millisecond ordering across state, runtime, and delivery leases", async () => {
    const orderedStateId = await insertAlertState();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET revision = 1,
                last_evaluated_at = '2026-07-17T10:00:00.100Z',
                updated_at = '2026-07-17T10:00:00.100Z'
          WHERE id = ?`,
      )
        .bind(orderedStateId)
        .run(),
    ).resolves.toBeDefined();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET revision = 2,
                last_evaluated_at = '2026-07-17T10:00:00.900Z',
                updated_at = '2026-07-17T10:00:00.900Z'
          WHERE id = ?`,
      )
        .bind(orderedStateId)
        .run(),
    ).resolves.toBeDefined();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET revision = 3,
                last_evaluated_at = '2026-07-17T10:00:00.500Z',
                updated_at = '2026-07-17T10:00:01.000Z'
          WHERE id = ?`,
      )
        .bind(orderedStateId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET revision = 3,
                last_evaluated_at = '2026-07-17T10:00:01Z',
                updated_at = '2026-07-17T10:00:01.000Z'
          WHERE id = ?`,
      )
        .bind(orderedStateId)
        .run(),
    ).rejects.toThrow();

    const cooldownStateId = await insertAlertState({
      ruleId: "pgid.registration.restricted_created.v1",
    });
    await insertSecurityAlert(cooldownStateId, 1, {
      ruleId: "pgid.registration.restricted_created.v1",
    });
    await recordFourClearSamples(cooldownStateId);
    const previousEvaluation = await env.PG72_ID_DB.prepare(
      "SELECT last_evaluated_at FROM alert_state WHERE id = ?",
    )
      .bind(cooldownStateId)
      .first<string>("last_evaluated_at");
    expect(previousEvaluation).not.toBeNull();
    const clearAt = new Date(Date.parse(previousEvaluation!) + 900).toISOString();
    const exactCooldown = cooldownAfter(clearAt);
    const shortCooldown = new Date(Date.parse(exactCooldown) - 1).toISOString();
    const clear = (cooldownUntil: string) =>
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET current_severity = 'none', consecutive_clears = 0,
                revision = revision + 1, last_notification_scheduled_at = NULL,
                cooldown_until = ?, last_cleared_at = ?,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      ).bind(
        cooldownUntil,
        clearAt,
        clearAt,
        clearAt,
        cooldownStateId,
      );
    await expect(clear(shortCooldown).run()).rejects.toThrow();
    await expect(clear(exactCooldown).run()).resolves.toBeDefined();
    const earlyExpiry = new Date(Date.parse(exactCooldown) - 400).toISOString();
    const expireCooldown = (evaluatedAt: string) =>
      env.PG72_ID_DB.prepare(
        `UPDATE alert_state
            SET cooldown_until = NULL, revision = revision + 1,
                last_evaluated_at = ?, updated_at = ?
          WHERE id = ?`,
      ).bind(evaluatedAt, evaluatedAt, cooldownStateId);
    await expect(expireCooldown(earlyExpiry).run()).rejects.toThrow();
    await expect(expireCooldown(exactCooldown).run()).resolves.toBeDefined();

    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_runtime_status (component, updated_at)
       VALUES ('delivery', '2026-07-17T10:00:00.000Z')`,
    ).run();
    const durationLeaseId = crypto.randomUUID();
    const acquireDurationLease = (leaseExpiresAt: string) =>
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET generation = 1, revision = 1, lease_id = ?,
                lease_expires_at = ?, updated_at = '2026-07-17T10:00:00.100Z'
          WHERE component = 'delivery'`,
      ).bind(durationLeaseId, leaseExpiresAt);
    await expect(
      acquireDurationLease("2026-07-17T10:05:00.101Z").run(),
    ).rejects.toThrow();
    await expect(
      acquireDurationLease("2026-07-17T10:05:00.100Z").run(),
    ).resolves.toBeDefined();

    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_runtime_status (component, updated_at)
       VALUES ('security_queue', '2026-07-17T10:00:00.000Z')`,
    ).run();
    const firstOwner = crypto.randomUUID();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET generation = 1, revision = 1, lease_id = ?,
              lease_expires_at = '2026-07-17T10:00:00.900Z',
              updated_at = '2026-07-17T10:00:00.100Z'
        WHERE component = 'security_queue'`,
    )
      .bind(firstOwner)
      .run();
    const replacementOwner = crypto.randomUUID();
    const replaceOwner = (updatedAt: string, leaseExpiresAt: string) =>
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET generation = 2, revision = 2, lease_id = ?,
                lease_expires_at = ?, updated_at = ?
          WHERE component = 'security_queue'`,
      ).bind(replacementOwner, leaseExpiresAt, updatedAt);
    await expect(
      replaceOwner(
        "2026-07-17T10:00:00.500Z",
        "2026-07-17T10:00:01.500Z",
      ).run(),
    ).rejects.toThrow();
    await expect(
      replaceOwner(
        "2026-07-17T10:00:00.900Z",
        "2026-07-17T10:00:01.900Z",
      ).run(),
    ).resolves.toBeDefined();

    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_runtime_status (component, updated_at)
       VALUES ('alert_queue', '2026-07-17T10:00:00.000Z')`,
    ).run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET revision = 1,
                last_started_at = '2026-07-17T10:00:00.900Z',
                last_success_at = '2026-07-17T10:00:00.100Z',
                updated_at = '2026-07-17T10:00:00.900Z'
          WHERE component = 'alert_queue'`,
      ).run(),
    ).rejects.toThrow();

    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_runtime_status
        (component, status, metric_sampled_at, backlog_count, backlog_bytes,
         oldest_message_age_seconds, nonzero_since_at,
         consecutive_nonzero_samples, updated_at)
       VALUES ('security_dlq', 'degraded', ?, 1, 10, 1, ?, 1, ?)`,
    )
      .bind(
        "2026-07-17T10:00:00.100Z",
        "2026-07-17T10:00:00.100Z",
        "2026-07-17T10:00:00.100Z",
      )
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET revision = 1,
                metric_sampled_at = '2026-07-17T10:01:00.900Z',
                consecutive_nonzero_samples = 2,
                updated_at = '2026-07-17T10:01:00.900Z'
          WHERE component = 'security_dlq'`,
      ).run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET revision = 1,
                metric_sampled_at = '2026-07-17T10:01:00.100Z',
                consecutive_nonzero_samples = 2,
                updated_at = '2026-07-17T10:01:00.100Z'
          WHERE component = 'security_dlq'`,
      ).run(),
    ).resolves.toBeDefined();
  });

  it("rejects noncanonical calendars without blocking exact UTC rollovers", async () => {
    for (const timestamp of [
      "2026-07-17 10:00:00.000",
      "2026-07-17T10:00:00Z",
      "2026-07-17T10:00:00.000+00:00",
      "2026-13-17T10:00:00.000Z",
      "2026-02-29T10:00:00.000Z",
      "2026-02-30T10:00:00.000Z",
      "2026-07-17T10:00:60.000Z",
      "2026-07-17T24:00:00.000Z",
    ]) {
      await expect(
        env.PG72_ID_DB.prepare(
          `INSERT INTO alert_runtime_status (component, updated_at)
           VALUES ('logout_queue', ?)`,
        )
          .bind(timestamp)
          .run(),
      ).rejects.toThrow();
    }

    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status (component, updated_at)
         VALUES ('logout_queue', '2024-02-29T23:59:59.800Z')`,
      ).run(),
    ).resolves.toBeDefined();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET generation = 1, revision = 1, lease_id = ?,
                lease_expires_at = '2024-02-29T24:00:00.900Z',
                updated_at = '2024-02-29T23:59:59.900Z'
          WHERE component = 'logout_queue'`,
      )
        .bind(crypto.randomUUID())
        .run(),
    ).rejects.toThrow();
    const rolloverLease = crypto.randomUUID();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET generation = 1, revision = 1, lease_id = ?,
                lease_expires_at = '2024-03-01T00:00:00.900Z',
                updated_at = '2024-02-29T23:59:59.900Z'
          WHERE component = 'logout_queue'`,
      )
        .bind(rolloverLease)
        .run(),
    ).resolves.toBeDefined();
    const replaceRolloverLease = (
      updatedAt: string,
      leaseExpiresAt: string,
    ) =>
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET generation = 2, revision = 2, lease_id = ?,
                lease_expires_at = ?, updated_at = ?
          WHERE component = 'logout_queue'`,
      ).bind(crypto.randomUUID(), leaseExpiresAt, updatedAt);
    await expect(
      replaceRolloverLease(
        "2024-03-01T00:00:00.500Z",
        "2024-03-01T00:00:01.500Z",
      ).run(),
    ).rejects.toThrow();
    await expect(
      replaceRolloverLease(
        "2024-03-01T00:00:00.900Z",
        "2024-03-01T00:00:01.900Z",
      ).run(),
    ).resolves.toBeDefined();
  });

  it("classifies delivery attempt expiry at the exact millisecond boundary", async () => {
    const stateId = await insertAlertState();
    const alertId = await insertSecurityAlert(stateId);
    const outboxId = await insertOutbox({ alertId });
    const leaseId = crypto.randomUUID();
    await claimOutbox(
      outboxId,
      leaseId,
      "2026-07-17T10:00:00.900Z",
      "2026-07-17T10:00:00.100Z",
    );
    const attemptId = crypto.randomUUID();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_delivery_attempt
        (id, outbox_id, replay_count, attempt_number, lease_id, outcome,
         resulting_status, error_code, started_at, completed_at)
       VALUES (?, ?, 0, 1, ?, 'in_flight', 'processing', NULL, ?, NULL)`,
    )
      .bind(
        attemptId,
        outboxId,
        leaseId,
        "2026-07-17T10:00:00.100Z",
      )
      .run();
    const expireAttempt = (completedAt: string) =>
      env.PG72_ID_DB.prepare(
        `UPDATE alert_delivery_attempt
            SET outcome = 'lease_expired', resulting_status = 'retry',
                error_code = 'lease_expired', completed_at = ?
          WHERE id = ?`,
      ).bind(completedAt, attemptId);
    await expect(
      expireAttempt("2026-07-17T10:00:00.500Z").run(),
    ).rejects.toThrow();
    await expect(
      expireAttempt("2026-07-17T10:00:00.900Z").run(),
    ).resolves.toBeDefined();
  });

  it("stores exact safe-integer runtime fences without widening alert caps", async () => {
    const tables = await env.PG72_ID_DB.prepare(
      `SELECT name, sql
         FROM sqlite_schema
        WHERE type = 'table'
          AND name IN (
            'alert_state', 'security_alert', 'alert_runtime_status',
            'alert_evaluator_bootstrap'
          )`,
    ).all<{ name: string; sql: string }>();
    const tableSql = new Map(
      tables.results.map(({ name, sql }) => [name, sql]),
    );
    expect(tableSql.get("alert_runtime_status")).toContain(
      '"generation" BETWEEN 0 AND 9007199254740991',
    );
    expect(tableSql.get("alert_runtime_status")).toContain(
      '"revision" BETWEEN 0 AND 9007199254740991',
    );
    expect(tableSql.get("alert_evaluator_bootstrap")).toContain(
      '"source_generation" BETWEEN 1 AND 9007199254740991',
    );
    expect(tableSql.get("alert_evaluator_bootstrap")).toContain(
      '"source_revision" BETWEEN 1 AND 9007199254740991',
    );
    expect(tableSql.get("alert_state")).toContain(
      '"generation" BETWEEN 0 AND 1000000',
    );
    expect(tableSql.get("alert_state")).toContain(
      '"revision" BETWEEN 0 AND 1000000000',
    );
    expect(tableSql.get("security_alert")).toContain(
      '"generation" BETWEEN 1 AND 1000000',
    );
    expect(tableSql.get("alert_runtime_status")).toContain(
      '"consecutive_nonzero_samples" BETWEEN 0 AND 1000000',
    );

    const roundTripTable = "alert_runtime_safe_integer_roundtrip";
    await env.PG72_ID_DB.prepare(
      `CREATE TABLE ${roundTripTable} (
        value INTEGER NOT NULL CHECK (
          typeof(value) = 'integer'
          AND value BETWEEN 0 AND 9007199254740991
        )
      )`,
    ).run();
    try {
      await env.PG72_ID_DB.prepare(
        `INSERT INTO ${roundTripTable} (value) VALUES (?)`,
      )
        .bind(Number.MAX_SAFE_INTEGER)
        .run();
      expect(
        await env.PG72_ID_DB.prepare(
          `SELECT value, typeof(value) AS storage_class
             FROM ${roundTripTable}`,
        ).first(),
      ).toEqual({
        storage_class: "integer",
        value: Number.MAX_SAFE_INTEGER,
      });
      await expect(
        env.PG72_ID_DB.prepare(
          `INSERT INTO ${roundTripTable} (value) VALUES (9007199254740992)`,
        ).run(),
      ).rejects.toThrow();
      await expect(
        env.PG72_ID_DB.prepare(
          `INSERT INTO ${roundTripTable} (value) VALUES (1.5)`,
        ).run(),
      ).rejects.toThrow();
    } finally {
      await env.PG72_ID_DB.prepare(`DROP TABLE ${roundTripTable}`).run();
    }
  });

  it("requires paired runtime leases, errors, and queue metric samples", async () => {
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, lease_id, updated_at)
         VALUES ('evaluator', ?, ?)`,
      )
        .bind(crypto.randomUUID(), NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, metric_sampled_at, backlog_count, updated_at)
         VALUES ('alert_queue', ?, 1, ?)`,
      )
        .bind(NOW, NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, consecutive_nonzero_samples, updated_at)
         VALUES ('delivery', 0, ?)`,
      )
        .bind(NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, metric_sampled_at, backlog_count, backlog_bytes,
           oldest_message_age_seconds, consecutive_nonzero_samples, updated_at)
         VALUES ('evaluator', ?, 0, 0, 0, 0, ?)`,
      )
        .bind(NOW, NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, status, metric_sampled_at, backlog_count, backlog_bytes,
           oldest_message_age_seconds, updated_at)
         VALUES ('alert_queue', 'degraded', ?, 1, 10, 5, ?)`,
      )
        .bind(NOW, NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, status, metric_sampled_at, backlog_count, backlog_bytes,
           oldest_message_age_seconds, nonzero_since_at,
           consecutive_nonzero_samples, updated_at)
         VALUES ('security_queue', 'degraded', ?, 1, 10, 5, ?, 1, ?)`,
      )
        .bind(NOW, "2026-07-17T10:01:00.000Z", NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, status, metric_sampled_at, backlog_count, backlog_bytes,
           oldest_message_age_seconds, nonzero_since_at,
           consecutive_nonzero_samples, updated_at)
         VALUES ('logout_queue', 'degraded', ?, 1, 10, 5, ?, 1, ?)`,
      )
        .bind("2026-07-17 10:00:00", NOW, NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, status, metric_sampled_at, backlog_count, backlog_bytes,
           oldest_message_age_seconds, nonzero_since_at,
           consecutive_nonzero_samples, updated_at)
         VALUES ('security_queue', 'degraded', ?, 1, 10, 5, ?, 2, ?)`,
      )
        .bind(NOW, "2026-07-17T09:59:00.000Z", NOW)
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_runtime_status
        (component, status, metric_sampled_at, backlog_count, backlog_bytes,
         oldest_message_age_seconds, nonzero_since_at,
         consecutive_nonzero_samples, updated_at)
       VALUES ('security_queue', 'degraded', ?, 1, 10, 5, ?, 1, ?)`,
    )
      .bind(NOW, NOW, NOW)
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET revision = 2, updated_at = ?
          WHERE component = 'security_queue'`,
      )
        .bind("2026-07-17T10:01:00.000Z")
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET generation = 2, revision = 1, updated_at = ?
          WHERE component = 'security_queue'`,
      )
        .bind("2026-07-17T10:01:00.000Z")
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET metric_sampled_at = '2026-07-17T09:59:00.000Z',
                revision = 1, updated_at = ?
          WHERE component = 'security_queue'`,
      )
        .bind("2026-07-17T10:01:00.000Z")
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET metric_sampled_at = ?, consecutive_nonzero_samples = 5,
                revision = 1, updated_at = ?
          WHERE component = 'security_queue'`,
      )
        .bind(
          "2026-07-17T10:01:00.000Z",
          "2026-07-17T10:01:00.000Z",
        )
        .run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET metric_sampled_at = ?, consecutive_nonzero_samples = 2,
              revision = 1, updated_at = ?
        WHERE component = 'security_queue'`,
    )
      .bind(
        "2026-07-17T10:01:00.000Z",
        "2026-07-17T10:01:00.000Z",
      )
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET metric_sampled_at = '2026-07-17T10:03:00.000Z',
                revision = 2, updated_at = '2026-07-17T10:02:00.000Z'
          WHERE component = 'security_queue'`,
      ).run(),
    ).rejects.toThrow();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET metric_sampled_at = ?, nonzero_since_at = ?,
              consecutive_nonzero_samples = 1, revision = 2, updated_at = ?
        WHERE component = 'security_queue'`,
    )
      .bind(
        "2026-07-17T10:03:00.000Z",
        "2026-07-17T10:03:00.000Z",
        "2026-07-17T10:03:00.000Z",
      )
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, status, metric_sampled_at, backlog_count, backlog_bytes,
           oldest_message_age_seconds, nonzero_since_at,
           consecutive_nonzero_samples, updated_at)
         VALUES ('audit_archive_dlq', 'degraded', ?, 1, 10, 5, ?, 1, ?)`,
      )
        .bind(NOW, NOW, NOW)
        .run(),
    ).resolves.toBeDefined();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, status, metric_sampled_at, backlog_count, backlog_bytes,
           oldest_message_age_seconds, consecutive_nonzero_samples, updated_at)
         VALUES ('alert_queue', 'healthy', ?, 0, 0, 0, 0, ?)`,
      )
        .bind(NOW, NOW)
        .run(),
    ).resolves.toBeDefined();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, status, last_error_at, last_error_code, updated_at)
         VALUES ('evaluator', 'degraded', ?, 'source_incomplete', ?)`,
      )
        .bind(NOW, NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, status, last_error_at, last_error_code, updated_at)
         VALUES ('delivery', 'failing', ?, 'arbitrary_error', ?)`,
      )
        .bind(NOW, NOW)
        .run(),
    ).rejects.toThrow();
  });

  it("anchors the first controlled evaluator success exactly once", async () => {
    const projectionSql = `SELECT
      b.component AS bootstrap_component,
      b.first_success_at AS first_success_at,
      b.source_generation AS source_generation,
      b.source_revision AS source_revision,
      r.component AS runtime_component,
      r.status AS runtime_status,
      r.generation AS runtime_generation,
      r.revision AS runtime_revision,
      r.last_started_at AS runtime_last_started_at,
      r.last_success_at AS runtime_last_success_at,
      r.last_error_at AS runtime_last_error_at,
      r.last_error_code AS runtime_last_error_code,
      r.updated_at AS runtime_updated_at
    FROM (SELECT 'evaluator' AS expected_component) AS e
    LEFT JOIN alert_evaluator_bootstrap AS b
      ON b.component = e.expected_component
    LEFT JOIN alert_runtime_status AS r
      ON r.component = e.expected_component`;
    const projectionKeys = [
      "bootstrap_component",
      "first_success_at",
      "source_generation",
      "source_revision",
      "runtime_component",
      "runtime_status",
      "runtime_generation",
      "runtime_revision",
      "runtime_last_started_at",
      "runtime_last_success_at",
      "runtime_last_error_at",
      "runtime_last_error_code",
      "runtime_updated_at",
    ];
    const preBootstrap = await env.PG72_ID_DB.prepare(projectionSql).first();
    expect(Object.keys(preBootstrap ?? {})).toEqual(projectionKeys);
    expect(preBootstrap).toEqual({
      bootstrap_component: null,
      first_success_at: null,
      source_generation: null,
      source_revision: null,
      runtime_component: null,
      runtime_status: null,
      runtime_generation: null,
      runtime_revision: null,
      runtime_last_started_at: null,
      runtime_last_success_at: null,
      runtime_last_error_at: null,
      runtime_last_error_code: null,
      runtime_updated_at: null,
    });

    const bootstrapColumns = await env.PG72_ID_DB.prepare(
      "PRAGMA table_info('alert_evaluator_bootstrap')",
    ).all<{ name: string }>();
    expect(bootstrapColumns.results.map(({ name }) => name)).toEqual([
      "component",
      "first_success_at",
      "source_generation",
      "source_revision",
    ]);
    const bootstrapForeignKeys = await env.PG72_ID_DB.prepare(
      "PRAGMA foreign_key_list('alert_evaluator_bootstrap')",
    ).all<{ from: string; on_delete: string; table: string; to: string }>();
    expect(bootstrapForeignKeys.results).toEqual([
      expect.objectContaining({
        from: "component",
        on_delete: "RESTRICT",
        table: "alert_runtime_status",
        to: "component",
      }),
    ]);

    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_runtime_status
          (component, status, last_started_at, last_success_at, updated_at)
         VALUES ('evaluator', 'healthy', ?, ?, ?)`,
      )
        .bind(NOW, NOW, NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_evaluator_bootstrap
          (component, first_success_at, source_generation)
         VALUES ('evaluator', ?, 1)`,
      )
        .bind(NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_evaluator_bootstrap
          (component, first_success_at, source_generation, source_revision)
         VALUES ('evaluator', ?, 1, 2)`,
      )
        .bind(NOW)
        .run(),
    ).rejects.toThrow();

    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_runtime_status (component, updated_at)
       VALUES ('evaluator', ?)`,
    )
      .bind(NOW)
      .run();
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, generation, revision, lease_id, lease_expires_at,
                last_started_at, last_success_at, last_error_at,
                last_error_code, watermark_at
           FROM alert_runtime_status WHERE component = 'evaluator'`,
      ).first(),
    ).toEqual({
      generation: 0,
      last_error_at: null,
      last_error_code: null,
      last_started_at: null,
      last_success_at: null,
      lease_expires_at: null,
      lease_id: null,
      revision: 0,
      status: "disabled",
      watermark_at: null,
    });
    expect(
      (
        await env.PG72_ID_DB.prepare(
          `INSERT INTO alert_evaluator_bootstrap
            (component, first_success_at, source_generation, source_revision)
           SELECT component, last_success_at, generation, revision
             FROM alert_runtime_status
            WHERE component = 'evaluator'
              AND status = 'healthy'
              AND last_success_at IS NOT NULL`,
        ).run()
      ).meta.changes,
    ).toBe(0);

    const startedAt = "2026-07-17T10:00:01.000Z";
    const acquired = await acquireAlertEvaluatorRun(env.PG72_ID_DB, {
      leaseDurationSeconds: 300,
      scheduledAt: startedAt,
      startedAt,
      triggerCron: "* * * * *",
    });
    if (!acquired || acquired.kind !== "acquired") {
      throw new Error("expected controlled evaluator run");
    }
    const leaseId = acquired.fence.leaseId;
    expect(await bindAlertEvaluatorRunAsOf(
      env.PG72_ID_DB,
      acquired.fence,
      { asOf: startedAt, boundAt: "2026-07-17T10:00:01.100Z" },
    )).toMatchObject({ kind: "committed" });
    for (const sourceId of ALERT_EVALUATOR_SOURCE_IDS) {
      expect(await recordAlertEvaluatorRunSource(
        env.PG72_ID_DB,
        acquired.fence,
        {
          asOf: startedAt,
          proof: {
            incompleteCount: 0,
            observationCount: 0,
            proofSha256: "A".repeat(43),
            sourceId,
            status: "complete",
          },
          recordedAt: "2026-07-17T10:00:01.200Z",
        },
      )).toBe("recorded");
    }
    expect(await sealAlertEvaluatorRunPlan(
      env.PG72_ID_DB,
      acquired.fence,
      { decisions: [], sealedAt: "2026-07-17T10:00:01.500Z" },
    )).toMatchObject({ kind: "committed" });
    const successAt = "2026-07-17T10:00:02.000Z";
    const successUpdate = () =>
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET status = 'healthy', revision = 2,
                lease_id = NULL, lease_expires_at = NULL,
                last_started_at = '2026-07-17T10:00:01.000Z',
                last_success_at = ?, updated_at = ?
          WHERE component = 'evaluator' AND lease_id = ?`,
      ).bind(successAt, successAt, leaseId);
    const explicitAnchor = (
      firstSuccessAt: string,
      sourceGeneration: number,
      sourceRevision: number,
    ) =>
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_evaluator_bootstrap
          (component, first_success_at, source_generation, source_revision)
         VALUES ('evaluator', ?, ?, ?)`,
      ).bind(firstSuccessAt, sourceGeneration, sourceRevision);

    await expect(
      env.PG72_ID_DB.batch([
        successUpdate(),
        explicitAnchor(successAt, 2, 2),
      ]),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.batch([
        successUpdate(),
        explicitAnchor(successAt, 1, 3),
      ]),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.batch([
        successUpdate(),
        explicitAnchor("2026-07-17T10:00:02Z", 1, 2),
      ]),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.batch([
        successUpdate(),
        explicitAnchor(successAt, 1.5, 2),
      ]),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.batch([
        successUpdate(),
        explicitAnchor(successAt, 1, 2.5),
      ]),
    ).rejects.toThrow();
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, generation, revision, lease_id, last_success_at
           FROM alert_runtime_status WHERE component = 'evaluator'`,
      ).first(),
    ).toEqual({
      generation: 1,
      last_success_at: null,
      lease_id: leaseId,
      revision: 1,
      status: "disabled",
    });

    expect(await recordAlertEvaluatorRunSuccess(
      env.PG72_ID_DB,
      acquired.fence,
      { completedAt: successAt },
    )).toMatchObject({ bootstrapCreated: true, kind: "committed" });
    const anchoredProjection = await env.PG72_ID_DB.prepare(projectionSql).first();
    expect(Object.keys(anchoredProjection ?? {})).toEqual(projectionKeys);
    expect(anchoredProjection).toEqual({
      bootstrap_component: "evaluator",
      first_success_at: successAt,
      source_generation: 1,
      source_revision: 2,
      runtime_component: "evaluator",
      runtime_status: "healthy",
      runtime_generation: 1,
      runtime_revision: 2,
      runtime_last_started_at: "2026-07-17T10:00:01.000Z",
      runtime_last_success_at: successAt,
      runtime_last_error_at: null,
      runtime_last_error_code: null,
      runtime_updated_at: successAt,
    });

    const failedRun = await acquireAlertEvaluatorRun(env.PG72_ID_DB, {
      leaseDurationSeconds: 300,
      scheduledAt: "2026-07-17T10:00:03.000Z",
      startedAt: "2026-07-17T10:00:03.000Z",
      triggerCron: "* * * * *",
    });
    if (!failedRun || failedRun.kind !== "acquired") {
      throw new Error("expected post-bootstrap evaluator run");
    }
    expect(await recordAlertEvaluatorRunFailure(
      env.PG72_ID_DB,
      failedRun.fence,
      {
        completedAt: "2026-07-17T10:00:04.000Z",
        errorCode: "evaluator_failed",
        status: "failing",
      },
    )).toMatchObject({ kind: "committed", run: { status: "failed" } });
    const anchoredRow = await env.PG72_ID_DB.prepare(
      "SELECT * FROM alert_evaluator_bootstrap WHERE component = 'evaluator'",
    ).first();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_evaluator_bootstrap SET first_success_at = ?
          WHERE component = 'evaluator'`,
      )
        .bind("2026-07-17T10:00:03.000Z")
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "DELETE FROM alert_evaluator_bootstrap WHERE component = 'evaluator'",
      ).run(),
    ).rejects.toThrow();
    await expect(
      explicitAnchor(successAt, 1, 2).run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO alert_evaluator_bootstrap
          (component, first_success_at, source_generation, source_revision)
         VALUES ('evaluator', ?, 1, 2)`,
      )
        .bind(successAt)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "DELETE FROM alert_runtime_status WHERE component = 'evaluator'",
      ).run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO alert_runtime_status (component, updated_at)
         VALUES ('evaluator', '2026-07-17T10:00:04.000Z')`,
      ).run(),
    ).rejects.toThrow();
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT * FROM alert_evaluator_bootstrap WHERE component = 'evaluator'",
      ).first(),
    ).toEqual(anchoredRow);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT status FROM alert_runtime_status WHERE component = 'evaluator'",
      ).first<string>("status"),
    ).toBe("failing");
    expect(
      (await env.PG72_ID_DB.prepare("PRAGMA foreign_key_check").all()).results,
    ).toEqual([]);
    expect(
      await env.PG72_ID_DB.prepare("PRAGMA quick_check").first<string>(
        "quick_check",
      ),
    ).toBe("ok");
  });
});
