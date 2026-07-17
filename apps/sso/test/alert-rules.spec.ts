import { describe, expect, it } from "vitest";

import {
  ALERT_HMAC_REFERENCE_DOMAINS,
  ALERT_QUEUE_COMPONENTS,
  ALERT_QUEUE_NAMES,
  ALERT_RULE_DEFINITIONS,
  ALERT_RULE_IDS,
  BOOTADMIN_PROTECTED_EVENTS,
  deriveAlertReferenceV1,
  evaluateAlertRule,
  HIGH_RISK_ADMIN_SUCCESS_EVENTS,
  HIGH_RISK_OAUTH_REPORT_REASONS,
  isHashedAlertReference,
  OAUTH_REPORT_REASONS,
  parseAlertObservation,
  parseAlertSelectedEvidence,
  RESTRICTED_ALERT_SURFACES,
  alertWindowsAt,
  type AlertRuleId,
  type Windowed,
} from "../worker/alert-rules";

const AS_OF = "2026-07-17T12:00:00.000Z";
const GLOBAL = { kind: "global" } as const;
const REFERENCE = { keyVersion: 1, value: "A".repeat(43) } as const;
const SUBJECT = { kind: "subject_hmac", reference: REFERENCE } as const;
const ACTOR = { kind: "actor_hmac", reference: REFERENCE } as const;
const CLIENT = { kind: "client_hmac", reference: REFERENCE } as const;
const QUEUE = { kind: "queue", queue: "logout_deliveries_dlq" } as const;

function windowed<T>(five: T, fifteen: T = five, sixty: T = fifteen): Windowed<T> {
  return { "5m": five, "15m": fifteen, "60m": sixty };
}

const gte = (metric: string, value: number) => ({ metric, op: "gte", value });
const ratio = (minDenominator: number, minNumerator: number, basisPoints: number) => ({
  basisPoints,
  denominator: "denominator",
  minDenominator,
  minNumerator,
  numerator: "numerator",
  op: "ratio_gte",
});
const any = (...clauses: readonly unknown[]) => ({ clauses, op: "any" });
const all = (...clauses: readonly unknown[]) => ({ clauses, op: "all" });

// Independent policy fixture. Do not derive this object from the implementation.
const EXPECTED_THRESHOLDS = {
  "pgid.registration.rate_limited.v1": {
    "5m": { critical: null, warning: gte("count", 5) },
    "15m": { critical: null, warning: gte("count", 10) },
    "60m": { critical: gte("count", 40), warning: null },
  },
  "pgid.registration.denied.v1": {
    "5m": { critical: null, warning: gte("count", 10) },
    "15m": { critical: null, warning: gte("count", 25) },
    "60m": { critical: gte("count", 100), warning: null },
  },
  "pgid.registration.challenge_unavailable.v1": {
    "5m": { critical: null, warning: ratio(5, 2, 2_000) },
    "15m": { critical: null, warning: ratio(15, 2, 2_000) },
    "60m": { critical: ratio(30, 5, 5_000), warning: null },
  },
  "pgid.registration.restricted_created.v1": {
    "5m": { critical: null, warning: gte("count", 7) },
    "15m": { critical: null, warning: gte("count", 20) },
    "60m": { critical: gte("count", 80), warning: null },
  },
  "pgid.restricted.sensitive_denied.v1": {
    "5m": { critical: null, warning: gte("count", 3) },
    "15m": { critical: null, warning: gte("count", 5) },
    "60m": {
      critical: any(
        gte("count", 20),
        all(gte("count", 5), gte("knownSurfaces", 2)),
      ),
      warning: null,
    },
  },
  "pgid.recovery.entry_abuse.v1": {
    "5m": {
      critical: null,
      warning: any(gte("rateLimited", 5), ratio(5, 5, 8_000)),
    },
    "15m": {
      critical: null,
      warning: any(gte("rateLimited", 10), ratio(15, 10, 8_000)),
    },
    "60m": {
      critical: any(gte("rateLimited", 40), ratio(30, 40, 9_000)),
      warning: null,
    },
  },
  "pgid.recovery.passkey_failure.v1": {
    "5m": { critical: null, warning: ratio(3, 3, 6_000) },
    "15m": { critical: null, warning: ratio(5, 5, 6_000) },
    "60m": { critical: ratio(10, 10, 8_000), warning: null },
  },
  "pgid.passkey.step_up_failure.v1": {
    "5m": { critical: null, warning: ratio(5, 3, 3_000) },
    "15m": { critical: null, warning: ratio(15, 5, 3_000) },
    "60m": { critical: ratio(30, 10, 6_000), warning: null },
  },
  "pgid.oauth.client_report.v1": {
    "5m": { critical: null, warning: gte("highRiskCount", 1) },
    "15m": { critical: null, warning: gte("count", 3) },
    "60m": {
      critical: any(
        all(gte("highRiskCount", 3), gte("distinctReporters", 2)),
        gte("count", 10),
      ),
      warning: null,
    },
  },
  "pgid.admin.sensitive_activity.v1": {
    "5m": {
      critical: null,
      warning: any(gte("successes", 1), gte("protectedDenials", 1)),
    },
    "15m": { critical: gte("count", 3), warning: null },
    "60m": { critical: gte("count", 10), warning: null },
  },
  "pgid.admin.directory_volume.v1": {
    "5m": { critical: null, warning: gte("count", 20) },
    "15m": { critical: null, warning: gte("count", 50) },
    "60m": { critical: gte("count", 200), warning: null },
  },
  "pgid.security.fanout_gap.v1": {
    "5m": { critical: null, warning: gte("missingOlderThan5mCount", 1) },
    "15m": { critical: gte("missingOlderThan15mCount", 1), warning: null },
    "60m": { critical: gte("missingOlderThan5mCount", 10), warning: null },
  },
  "pgid.logout.delivery_health.v1": {
    "5m": {
      critical: any(gte("dead", 1), ratio(5, 1, 5_000)),
      warning: any(
        gte("oldestUnresolvedAgeSeconds", 120),
        gte("leaseExpired", 1),
        ratio(5, 1, 2_000),
      ),
    },
    "15m": {
      critical: any(
        gte("dead", 1),
        gte("oldestUnresolvedAgeSeconds", 300),
        gte("leaseExpired", 3),
        ratio(10, 1, 5_000),
      ),
      warning: ratio(10, 1, 2_000),
    },
    "60m": {
      critical: any(gte("dead", 1), gte("leaseExpired", 5), ratio(20, 1, 5_000)),
      warning: ratio(20, 1, 2_000),
    },
  },
  "pgid.alert.runtime_health.v1": {
    "5m": {
      critical: null,
      warning: any(gte("evaluatorAgeSeconds", 181), gte("outboxDueAgeSeconds", 121)),
    },
    "15m": {
      critical: any(
        gte("evaluatorMissing", 1),
        gte("evaluatorAgeSeconds", 301),
        gte("outboxDueAgeSeconds", 301),
      ),
      warning: null,
    },
    "60m": { critical: gte("deadOutbox", 1), warning: null },
  },
  "pgid.queue.dlq_approximate.v1": {
    "5m": { critical: null, warning: gte("depth", 1) },
    "15m": {
      critical: any(
        gte("depth", 10),
        gte("consecutiveNonzeroSamples", 15),
      ),
      warning: null,
    },
    "60m": { critical: null, warning: null },
  },
} as const;

// Independent collection contract. Every field is repeated literally so a source
// change cannot make this fixture pass by sharing implementation constants.
const EXPECTED_SOURCES = {
  "pgid.registration.rate_limited.v1": {
    dimensionColumn: null,
    eventIdColumn: "id",
    eventTypeColumn: "event_type",
    filters: [{
      eventTypes: ["registration.rate_limited"],
      metricRoles: ["count"],
      outcome: "denied",
    }],
    includeGlobal: true,
    metadataColumn: "metadata_json",
    mode: "audit_event",
    occurredAtColumn: "occurred_at",
    outcomeColumn: "outcome",
    table: "audit_event",
  },
  "pgid.registration.denied.v1": {
    dimensionColumn: null,
    eventIdColumn: "id",
    eventTypeColumn: "event_type",
    filters: [{
      eventTypes: ["registration.denied"],
      metricRoles: ["count"],
      outcome: "denied",
    }],
    includeGlobal: true,
    metadataColumn: "metadata_json",
    mode: "audit_event",
    occurredAtColumn: "occurred_at",
    outcomeColumn: "outcome",
    table: "audit_event",
  },
  "pgid.registration.challenge_unavailable.v1": {
    dimensionColumn: null,
    eventIdColumn: "id",
    eventTypeColumn: "event_type",
    filters: [
      {
        eventTypes: ["registration.challenge_unavailable"],
        metricRoles: ["numerator", "denominator"],
        outcome: "failure",
      },
      {
        eventTypes: ["registration.challenge_denied"],
        metricRoles: ["denominator"],
        outcome: "denied",
      },
      {
        eventTypes: ["registration.intent_created"],
        metricRoles: ["denominator"],
        outcome: "success",
      },
    ],
    includeGlobal: true,
    metadataColumn: "metadata_json",
    mode: "audit_event",
    occurredAtColumn: "occurred_at",
    outcomeColumn: "outcome",
    table: "audit_event",
  },
  "pgid.registration.restricted_created.v1": {
    dimensionColumn: null,
    eventIdColumn: "id",
    eventTypeColumn: "event_type",
    filters: [{
      eventTypes: ["user.created"],
      metadata: { key: "accessLevel", values: ["restricted"] },
      metricRoles: ["count"],
      outcome: "success",
    }],
    includeGlobal: true,
    metadataColumn: "metadata_json",
    mode: "audit_event",
    occurredAtColumn: "occurred_at",
    outcomeColumn: "outcome",
    table: "audit_event",
  },
  "pgid.restricted.sensitive_denied.v1": {
    dimensionColumn: "subject_id",
    eventIdColumn: "id",
    eventTypeColumn: "event_type",
    filters: [{
      eventTypes: ["account.restricted_action_denied"],
      metadata: {
        key: "surface",
        values: [
          "provider_link",
          "clients.manage",
          "clients.manage_all",
          "users.read",
          "users.invite",
          "users.manage",
          "users.assign_roles",
        ],
      },
      metricRoles: ["count", "known_surfaces"],
      outcome: "denied",
    }],
    includeGlobal: false,
    metadataColumn: "metadata_json",
    mode: "audit_event",
    occurredAtColumn: "occurred_at",
    outcomeColumn: "outcome",
    table: "audit_event",
  },
  "pgid.recovery.entry_abuse.v1": {
    dimensionColumn: null,
    eventIdColumn: "id",
    eventTypeColumn: "event_type",
    filters: [
      {
        eventTypes: ["recovery.rate_limited"],
        metricRoles: ["rate_limited"],
        outcome: "denied",
      },
      {
        eventTypes: ["recovery.entry_denied"],
        metricRoles: ["numerator", "denominator"],
        outcome: "denied",
      },
      {
        eventTypes: ["recovery.started"],
        metricRoles: ["denominator"],
        outcome: "success",
      },
    ],
    includeGlobal: true,
    metadataColumn: "metadata_json",
    mode: "audit_event",
    occurredAtColumn: "occurred_at",
    outcomeColumn: "outcome",
    table: "audit_event",
  },
  "pgid.recovery.passkey_failure.v1": {
    dimensionColumn: "subject_id",
    eventIdColumn: "id",
    eventTypeColumn: "event_type",
    filters: [
      {
        eventTypes: ["recovery.passkey_failed"],
        metricRoles: ["numerator", "denominator"],
        outcome: "denied",
      },
      {
        eventTypes: ["recovery.completed"],
        metricRoles: ["denominator"],
        outcome: "success",
      },
    ],
    includeGlobal: true,
    metadataColumn: "metadata_json",
    mode: "audit_event",
    occurredAtColumn: "occurred_at",
    outcomeColumn: "outcome",
    table: "audit_event",
  },
  "pgid.passkey.step_up_failure.v1": {
    dimensionColumn: "subject_id",
    eventIdColumn: "id",
    eventTypeColumn: "event_type",
    filters: [
      {
        eventTypes: ["passkey.step_up_failed"],
        metricRoles: ["numerator", "denominator"],
        outcome: "denied",
      },
      {
        eventTypes: ["passkey.step_up_succeeded"],
        metricRoles: ["denominator"],
        outcome: "success",
      },
    ],
    includeGlobal: true,
    metadataColumn: "metadata_json",
    mode: "audit_event",
    occurredAtColumn: "occurred_at",
    outcomeColumn: "outcome",
    table: "audit_event",
  },
  "pgid.oauth.client_report.v1": {
    allReasons: ["impersonation", "phishing", "scope_abuse", "other"],
    completenessPredicate: "reporter_user_id_or_reporter_ref_present",
    coverageLookbackSeconds: 3_600,
    createdAtColumn: "created_at",
    dimensionColumn: "client_id",
    hashVersion: 1,
    highRiskReasons: ["impersonation", "phishing"],
    missingReporterIdentity: "null_distinct_reporters",
    mode: "oauth_client_report",
    reasonColumn: "reason",
    reporterRefColumn: "reporter_ref",
    reporterRefDomain: "reporter_hmac",
    reporterRefHashVersionColumn: "reporter_ref_hash_version",
    reporterUserIdColumn: "reporter_user_id",
    table: "oauth_client_report",
  },
  "pgid.admin.sensitive_activity.v1": {
    actorRefColumn: "actor_ref",
    actorRefHashVersionColumn: "actor_ref_hash_version",
    completenessPredicate: "actor_user_id_or_actor_ref_present",
    coverageLookbackSeconds: 3_600,
    dimensionColumn: "actor_user_id",
    eventIdColumn: "id",
    eventTypeColumn: "event_type",
    filters: [
      {
        eventTypes: [
          "invitation.created",
          "logout_delivery.replayed",
          "oauth_client.created",
          "oauth_client.deleted",
          "oauth_client.disabled",
          "oauth_client.enabled",
          "oauth_client.secret_rotated",
          "oauth_client.trust_updated",
          "oauth_client.updated",
          "user.access_promoted",
          "user.access_restricted",
          "user.deleted",
          "user.reactivated",
          "user.role_changed",
          "user.sessions_revoked",
          "user.suspended",
        ],
        metricRoles: ["count", "successes"],
        outcome: "success",
      },
      {
        eventTypes: [
          "user.access_promoted",
          "user.access_restricted",
          "user.deleted",
          "user.reactivated",
          "user.role_changed",
          "user.sessions_revoked",
          "user.suspended",
        ],
        metadata: { key: "reason", values: ["bootadmin_protected"] },
        metricRoles: ["count", "protected_denials"],
        outcome: "denied",
      },
    ],
    includeGlobal: false,
    metadataColumn: "metadata_json",
    missingActorIdentity: "source_incomplete",
    mode: "audit_event",
    occurredAtColumn: "occurred_at",
    outcomeColumn: "outcome",
    table: "audit_event",
  },
  "pgid.admin.directory_volume.v1": {
    actorRefColumn: "actor_ref",
    actorRefHashVersionColumn: "actor_ref_hash_version",
    completenessPredicate: "actor_user_id_or_actor_ref_present",
    coverageLookbackSeconds: 3_600,
    dimensionColumn: "actor_user_id",
    eventIdColumn: "id",
    eventTypeColumn: "event_type",
    filters: [{
      eventTypes: ["admin.users_listed"],
      metricRoles: ["count"],
      outcome: "success",
    }],
    includeGlobal: false,
    metadataColumn: "metadata_json",
    missingActorIdentity: "source_incomplete",
    mode: "audit_event",
    occurredAtColumn: "occurred_at",
    outcomeColumn: "outcome",
    table: "audit_event",
  },
  "pgid.security.fanout_gap.v1": {
    detectionOnly: true,
    dimension: "global",
    graceSeconds: 300,
    join: "left",
    lookbackSeconds: 3_600,
    markerEventIdColumn: "event_id",
    markerTable: "security_event_delivery",
    mode: "audit_fanout",
    sourceIdColumn: "id",
    sourceTable: "audit_event",
    sourceTimeColumn: "occurred_at",
  },
  "pgid.logout.delivery_health.v1": {
    currentSnapshot: {
      clientIdColumn: "client_id",
      createdAtColumn: "created_at",
      deadStatus: "dead",
      oldestAgeSecondsSemantics: "as_of_minus_oldest_current_unresolved_created_at_floor_seconds",
      scope: "all_current_rows_at_as_of",
      statusColumn: "status",
      unresolvedStatuses: ["pending", "processing", "retry", "dead"],
    },
    dimensions: ["global", "client_id"],
    mode: "logout_delivery",
    windows: {
      attemptCompletedAtColumn: "completed_at",
      attemptCohortScope: "completed_at_in_half_open_window",
      attemptDeliveryIdColumn: "delivery_id",
      attemptOutcomeColumn: "outcome",
      attemptTable: "logout_delivery_attempt",
      deliveryClientIdColumn: "client_id",
      deliveryCohortColumn: "created_at",
      deliveryCohortScope: "created_at_in_half_open_window",
      deliveryIdColumn: "id",
      deliveryStatusColumn: "status",
      deliveryTable: "logout_delivery",
      eligibleStatuses: ["pending", "processing", "retry", "delivered", "dead"],
      leaseExpiredOutcome: "lease_expired",
      unresolvedStatuses: ["pending", "processing", "retry", "dead"],
    },
  },
  "pgid.alert.runtime_health.v1": {
    dimension: "global",
    evaluator: {
      ageSecondsSemantics: "as_of_minus_last_success_at_floor_seconds",
      bootstrapRequirement: "enabled_row_created_before_rule_evaluation",
      component: "evaluator",
      componentColumn: "component",
      enabledStatuses: ["healthy", "degraded", "failing", "unavailable"],
      lastSuccessAtColumn: "last_success_at",
      nullAgeSemantics: "last_success_at_is_null",
      statusColumn: "status",
    },
    mode: "alert_runtime",
    outbox: {
      currentDeadCountSemantics: "status_equals_dead_at_as_of",
      currentDeadStatus: "dead",
      dueAgeSecondsSemantics: "as_of_minus_oldest_due_or_expired_time_floor_seconds",
      dueAgeSecondsNullSemantics: "no_due_or_expired_work_at_as_of",
      dueStatuses: ["pending", "retry"],
      dueTimeColumn: "next_attempt_at",
      expiredProcessingStatus: "processing",
      expiredProcessingTimeColumn: "lease_expires_at",
      statusColumn: "status",
      table: "alert_outbox",
    },
    runtimeTable: "alert_runtime_status",
  },
  "pgid.queue.dlq_approximate.v1": {
    backlogBytesBindingField: "backlogBytes",
    backlogBytesColumn: "backlog_bytes",
    backlogBytesMaximum: 1_000_000_000_000,
    backlogCountBindingField: "backlogCount",
    backlogCountColumn: "backlog_count",
    backlogCountMaximum: 1_000_000_000,
    componentColumn: "component",
    consecutiveNonzeroSamplesColumn: "consecutive_nonzero_samples",
    consecutiveNonzeroSamplesMaximum: 1_000_000,
    criticalDurationSeconds: 900,
    dimension: "queue_name",
    invalidBindingMetrics: "unknown",
    method: "metrics",
    metricSampledAtColumn: "metric_sampled_at",
    mode: "queue_metrics",
    nonzeroSinceAtColumn: "nonzero_since_at",
    numericValidation: "finite_safe_nonnegative_integer",
    oldestMessageAgeSecondsColumn: "oldest_message_age_seconds",
    oldestMessageAgeSecondsMaximum: 1_000_000_000,
    oldestMessageTimestampBindingField: "oldestMessageTimestamp",
    oldestMessageTimestampNormalization: "sampled_at_minus_oldest_message_timestamp_floor_seconds",
    queueComponentByName: {
      alert_deliveries_dlq: "alert_dlq",
      audit_archive_dlq: "audit_archive_dlq",
      logout_deliveries_dlq: "logout_dlq",
      security_events_dlq: "security_dlq",
    },
    queueNames: [
      "security_events_dlq",
      "logout_deliveries_dlq",
      "alert_deliveries_dlq",
      "audit_archive_dlq",
    ],
    sampleCadenceSeconds: 60,
    streakStateTable: "alert_runtime_status",
  },
} as const;

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

async function expectedHmac(keyBytes: Uint8Array, kind: string, raw: string): Promise<string> {
  const keyMaterial = new ArrayBuffer(keyBytes.length);
  new Uint8Array(keyMaterial).set(keyBytes);
  const key = await crypto.subtle.importKey(
    "raw",
    keyMaterial,
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign"],
  );
  return base64Url(new Uint8Array(await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`pgid-alert-v1\0${kind}\0${raw}`),
  )));
}

function runtimeObservation(
  evaluatorAgeSeconds: number | null,
  outboxDueAgeSeconds: number | null,
  deadOutbox = 0,
) {
  return {
    asOf: AS_OF,
    dimension: GLOBAL,
    ruleId: "pgid.alert.runtime_health.v1",
    snapshot: { deadOutbox, evaluatorAgeSeconds, outboxDueAgeSeconds },
  };
}

function queueObservation(snapshot: {
  backlogBytes: unknown;
  backlogCount: unknown;
  consecutiveNonzeroSamples: unknown;
  nonzeroSinceAt: unknown;
  oldestMessageTimestamp?: unknown;
  sampledAt: unknown;
}) {
  return {
    asOf: AS_OF,
    dimension: QUEUE,
    ruleId: "pgid.queue.dlq_approximate.v1",
    snapshot,
  };
}

describe("canonical alert contracts", () => {
  it("deep-matches the independent 15-rule threshold matrix", () => {
    expect(ALERT_RULE_IDS).toHaveLength(15);
    expect(Object.keys(ALERT_RULE_DEFINITIONS)).toEqual([...ALERT_RULE_IDS]);
    expect(Object.fromEntries(
      ALERT_RULE_IDS.map((id) => [id, ALERT_RULE_DEFINITIONS[id].thresholds]),
    )).toEqual(EXPECTED_THRESHOLDS);
  });

  it("deep-matches all 15 independent collection descriptors", () => {
    expect(Object.fromEntries(
      ALERT_RULE_IDS.map((id) => [id, ALERT_RULE_DEFINITIONS[id].source]),
    )).toEqual(EXPECTED_SOURCES);
  });

  it("binds every rule to its exact source family and resolution mode", () => {
    const modes = Object.fromEntries(ALERT_RULE_IDS.map((id) => [
      id,
      ALERT_RULE_DEFINITIONS[id].source.mode,
    ]));
    expect(modes).toEqual({
      "pgid.registration.rate_limited.v1": "audit_event",
      "pgid.registration.denied.v1": "audit_event",
      "pgid.registration.challenge_unavailable.v1": "audit_event",
      "pgid.registration.restricted_created.v1": "audit_event",
      "pgid.restricted.sensitive_denied.v1": "audit_event",
      "pgid.recovery.entry_abuse.v1": "audit_event",
      "pgid.recovery.passkey_failure.v1": "audit_event",
      "pgid.passkey.step_up_failure.v1": "audit_event",
      "pgid.oauth.client_report.v1": "oauth_client_report",
      "pgid.admin.sensitive_activity.v1": "audit_event",
      "pgid.admin.directory_volume.v1": "audit_event",
      "pgid.security.fanout_gap.v1": "audit_fanout",
      "pgid.logout.delivery_health.v1": "logout_delivery",
      "pgid.alert.runtime_health.v1": "alert_runtime",
      "pgid.queue.dlq_approximate.v1": "queue_metrics",
    });
    expect(ALERT_RULE_DEFINITIONS["pgid.security.fanout_gap.v1"]).toMatchObject({
      resolutionMode: "manual",
      source: {
        detectionOnly: true,
        graceSeconds: 300,
        lookbackSeconds: 3_600,
        markerTable: "security_event_delivery",
        sourceTable: "audit_event",
      },
    });
    for (const id of ALERT_RULE_IDS.filter((candidate) =>
      candidate !== "pgid.security.fanout_gap.v1"
    )) {
      expect(ALERT_RULE_DEFINITIONS[id].resolutionMode).toBe("automatic");
    }
    expect(ALERT_RULE_DEFINITIONS["pgid.queue.dlq_approximate.v1"].sourceKind)
      .toBe("queue_approximate");
    expect(ALERT_RULE_DEFINITIONS["pgid.queue.dlq_approximate.v1"].source)
      .toMatchObject({
        backlogCountColumn: "backlog_count",
        componentColumn: "component",
        consecutiveNonzeroSamplesColumn: "consecutive_nonzero_samples",
        criticalDurationSeconds: 900,
        metricSampledAtColumn: "metric_sampled_at",
        nonzeroSinceAtColumn: "nonzero_since_at",
        queueComponentByName: ALERT_QUEUE_COMPONENTS,
        sampleCadenceSeconds: 60,
        streakStateTable: "alert_runtime_status",
      });
    for (const id of ALERT_RULE_IDS.filter((candidate) =>
      candidate !== "pgid.queue.dlq_approximate.v1"
    )) {
      expect(ALERT_RULE_DEFINITIONS[id].sourceKind).toBe("d1_exact");
    }
  });

  it("pins the exact sensitive source allowlists", () => {
    expect(RESTRICTED_ALERT_SURFACES).toEqual([
      "provider_link",
      "clients.manage",
      "clients.manage_all",
      "users.read",
      "users.invite",
      "users.manage",
      "users.assign_roles",
    ]);
    expect(OAUTH_REPORT_REASONS).toEqual([
      "impersonation",
      "phishing",
      "scope_abuse",
      "other",
    ]);
    expect(HIGH_RISK_OAUTH_REPORT_REASONS).toEqual(["impersonation", "phishing"]);
    expect(HIGH_RISK_ADMIN_SUCCESS_EVENTS).toEqual([
      "invitation.created",
      "logout_delivery.replayed",
      "oauth_client.created",
      "oauth_client.deleted",
      "oauth_client.disabled",
      "oauth_client.enabled",
      "oauth_client.secret_rotated",
      "oauth_client.trust_updated",
      "oauth_client.updated",
      "user.access_promoted",
      "user.access_restricted",
      "user.deleted",
      "user.reactivated",
      "user.role_changed",
      "user.sessions_revoked",
      "user.suspended",
    ]);
    expect(BOOTADMIN_PROTECTED_EVENTS).toEqual([
      "user.access_promoted",
      "user.access_restricted",
      "user.deleted",
      "user.reactivated",
      "user.role_changed",
      "user.sessions_revoked",
      "user.suspended",
    ]);
    expect(ALERT_QUEUE_NAMES).toEqual([
      "security_events_dlq",
      "logout_deliveries_dlq",
      "alert_deliveries_dlq",
      "audit_archive_dlq",
    ]);
    expect(ALERT_QUEUE_COMPONENTS).toEqual({
      alert_deliveries_dlq: "alert_dlq",
      audit_archive_dlq: "audit_archive_dlq",
      logout_deliveries_dlq: "logout_dlq",
      security_events_dlq: "security_dlq",
    });
    const adminSource = ALERT_RULE_DEFINITIONS["pgid.admin.sensitive_activity.v1"].source;
    expect(adminSource.mode).toBe("audit_event");
    if (adminSource.mode !== "audit_event") throw new Error("unexpected source");
    expect(adminSource.filters.map(({ metricRoles }) => metricRoles)).toEqual([
      ["count", "successes"],
      ["count", "protected_denials"],
    ]);
  });

  it("builds exact half-open UTC windows from injected time", () => {
    expect(alertWindowsAt(AS_OF)).toEqual([
      {
        endExclusive: AS_OF,
        key: "5m",
        minutes: 5,
        startInclusive: "2026-07-17T11:55:00.000Z",
      },
      {
        endExclusive: AS_OF,
        key: "15m",
        minutes: 15,
        startInclusive: "2026-07-17T11:45:00.000Z",
      },
      {
        endExclusive: AS_OF,
        key: "60m",
        minutes: 60,
        startInclusive: "2026-07-17T11:00:00.000Z",
      },
    ]);
    expect(() => alertWindowsAt("2026-07-17T12:00:00Z")).toThrow("canonical UTC ISO");
  });
});

describe("redacted observation parsing", () => {
  it("derives the exact v1 domain-separated WebCrypto HMAC", async () => {
    const keyBytes = Uint8Array.from({ length: 32 }, (_, index) => index);
    const key = base64Url(keyBytes);
    const subject = await deriveAlertReferenceV1(key, "subject_hmac", "subject-1");
    expect(subject).toEqual({
      keyVersion: 1,
      value: await expectedHmac(keyBytes, "subject_hmac", "subject-1"),
    });
    expect(subject.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(subject.value).not.toContain("subject-1");
    const domains = await Promise.all(ALERT_HMAC_REFERENCE_DOMAINS.map((domain) =>
      deriveAlertReferenceV1(key, domain, "subject-1")
    ));
    expect(new Set(domains.map(({ value }) => value)).size).toBe(4);
    expect(domains[3]).toEqual({
      keyVersion: 1,
      value: await expectedHmac(keyBytes, "reporter_hmac", "subject-1"),
    });
    const otherKey = base64Url(Uint8Array.from({ length: 32 }, (_, index) => index + 1));
    expect(await deriveAlertReferenceV1(otherKey, "subject_hmac", "subject-1"))
      .not.toEqual(subject);
    const canonicalZeroKey = base64Url(new Uint8Array(32));
    const noncanonical = `${canonicalZeroKey.slice(0, -1)}B`;
    await expect(deriveAlertReferenceV1(noncanonical, "subject_hmac", "subject-1"))
      .rejects.toThrow("32-byte");
    await expect(deriveAlertReferenceV1("short", "subject_hmac", "subject-1"))
      .rejects.toThrow("32-byte");
  });

  it("accepts only exact HMAC reference objects", () => {
    expect(isHashedAlertReference(REFERENCE)).toBe(true);
    expect(isHashedAlertReference({ ...REFERENCE, rawSubject: "redacted" })).toBe(false);
    expect(isHashedAlertReference({ keyVersion: 0, value: "A".repeat(43) })).toBe(false);
    expect(isHashedAlertReference({ keyVersion: 1, value: "raw-user-id" })).toBe(false);
    expect(isHashedAlertReference({
      keyVersion: 1,
      value: `${"A".repeat(42)}B`,
    })).toBe(false);
  });

  it("rejects extra/missing keys and unsupported runtime dimensions", () => {
    const valid = {
      asOf: AS_OF,
      dimension: SUBJECT,
      ruleId: "pgid.restricted.sensitive_denied.v1",
      windows: windowed(
        { count: 3, knownSurfaces: 1 },
        { count: 3, knownSurfaces: 1 },
        { count: 3, knownSurfaces: 1 },
      ),
    };
    expect(() => parseAlertObservation({ ...valid, rawSubject: "redacted" })).toThrow(
      "canonical keys",
    );
    expect(() => parseAlertObservation({
      ...valid,
      dimension: { ...SUBJECT, rawSubject: "redacted" },
    })).toThrow("canonical keys");
    expect(() => parseAlertObservation({
      ...valid,
      dimension: {
        kind: "subject_hmac",
        reference: { ...REFERENCE, rawSubject: "redacted" },
      },
    })).toThrow("canonical keys");
    expect(() => parseAlertObservation({
      ...valid,
      dimension: { kind: "reporter_hmac", reference: REFERENCE },
    })).toThrow("not supported");
    expect(() => parseAlertObservation({
      ...valid,
      windows: {
        ...valid.windows,
        "5m": { ...valid.windows["5m"], raw: 1 },
      },
    })).toThrow("canonical keys");
    expect(() => parseAlertObservation({
      asOf: AS_OF,
      dimension: { kind: "queue", queue: "not_a_real_queue" },
      ruleId: "pgid.queue.dlq_approximate.v1",
      snapshot: {
        backlogBytes: 0,
        backlogCount: 0,
        consecutiveNonzeroSamples: 0,
        nonzeroSinceAt: null,
        oldestMessageTimestamp: null,
        sampledAt: AS_OF,
      },
    })).toThrow("Queue name");
  });

  it("reconstructs dimensions instead of echoing caller objects", () => {
    const input = {
      asOf: AS_OF,
      dimension: SUBJECT,
      ruleId: "pgid.restricted.sensitive_denied.v1",
      windows: windowed(
        { count: 3, knownSurfaces: 1 },
        { count: 3, knownSurfaces: 1 },
        { count: 3, knownSurfaces: 1 },
      ),
    };
    const evaluation = evaluateAlertRule(input);
    expect(evaluation.dimension).toEqual(SUBJECT);
    expect(evaluation.dimension).not.toBe(input.dimension);
    if (evaluation.dimension.kind === "subject_hmac") {
      expect(evaluation.dimension.reference).not.toBe(input.dimension.reference);
    }
  });

  it("rejects impossible nested event cohorts", () => {
    const invalid = {
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.registration.denied.v1",
      windows: windowed({ count: 10 }, { count: 9 }, { count: 20 }),
    };
    expect(() => evaluateAlertRule(invalid)).toThrow("nondecreasing");
  });

  it("parses nullable OAuth reporter coverage without accepting shadow fields", () => {
    const partial = {
      asOf: AS_OF,
      dimension: CLIENT,
      ruleId: "pgid.oauth.client_report.v1",
      windows: windowed(
        { count: 0, distinctReporters: 0, highRiskCount: 0 },
        { count: 0, distinctReporters: 0, highRiskCount: 0 },
        { count: 3, distinctReporters: null, highRiskCount: 3 },
      ),
    };
    expect(parseAlertObservation(partial)).toEqual(partial);
    expect(() => parseAlertObservation({
      ...partial,
      reporterCoverage: "partial",
    })).toThrow("canonical keys");
    expect(() => parseAlertObservation({
      ...partial,
      windows: {
        ...partial.windows,
        "60m": {
          count: 3,
          highRiskCount: 3,
          reporterCoverage: "partial",
        },
      },
    })).toThrow("canonical keys");
    expect(() => parseAlertObservation({
      ...partial,
      windows: {
        ...partial.windows,
        "60m": { count: 3, distinctReporters: "partial", highRiskCount: 3 },
      },
    })).toThrow("persistence domain");
    expect(() => parseAlertObservation({
      ...partial,
      windows: {
        ...partial.windows,
        "5m": { count: 1, distinctReporters: null, highRiskCount: 0 },
        "15m": { count: 1, distinctReporters: 1, highRiskCount: 0 },
      },
    })).toThrow("remain unknown");
  });
});

describe("rule evaluation", () => {
  it("removes undocumented carry-forward warnings", () => {
    const cases = [
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.registration.challenge_unavailable.v1",
        windows: windowed(
          { denominator: 0, numerator: 0 },
          { denominator: 0, numerator: 0 },
          { denominator: 30, numerator: 6 },
        ),
      },
      {
        asOf: AS_OF,
        dimension: SUBJECT,
        ruleId: "pgid.restricted.sensitive_denied.v1",
        windows: windowed(
          { count: 0, knownSurfaces: 0 },
          { count: 0, knownSurfaces: 0 },
          { count: 5, knownSurfaces: 1 },
        ),
      },
      {
        asOf: AS_OF,
        dimension: SUBJECT,
        ruleId: "pgid.recovery.passkey_failure.v1",
        windows: windowed(
          { denominator: 0, numerator: 0 },
          { denominator: 0, numerator: 0 },
          { denominator: 10, numerator: 6 },
        ),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.passkey.step_up_failure.v1",
        windows: windowed(
          { denominator: 0, numerator: 0 },
          { denominator: 0, numerator: 0 },
          { denominator: 30, numerator: 9 },
        ),
      },
      {
        asOf: AS_OF,
        dimension: CLIENT,
        ruleId: "pgid.oauth.client_report.v1",
        windows: windowed(
          { count: 0, distinctReporters: 0, highRiskCount: 0 },
          { count: 0, distinctReporters: 0, highRiskCount: 0 },
          { count: 3, distinctReporters: 1, highRiskCount: 0 },
        ),
      },
    ];
    expect(cases.map((entry) => evaluateAlertRule(entry).severity))
      .toEqual(["none", "none", "none", "none", "none"]);
  });

  it("makes a 50 percent five-minute logout cohort critical", () => {
    const evaluation = evaluateAlertRule({
      asOf: AS_OF,
      current: {
        currentDead: 0,
        currentUnresolved: 3,
        oldestUnresolvedAgeSeconds: 0,
      },
      dimension: GLOBAL,
      ruleId: "pgid.logout.delivery_health.v1",
      windows: windowed(
        {
          eligible: 5,
          leaseExpired: 0,
          unresolved: 3,
        },
        {
          eligible: 5,
          leaseExpired: 0,
          unresolved: 3,
        },
        {
          eligible: 5,
          leaseExpired: 0,
          unresolved: 3,
        },
      ),
    });
    expect(evaluation).toMatchObject({
      immediateCritical: false,
      selectedEvidence: {
        metricName: "ratio",
        minimumNumeratorCount: 1,
        minimumSampleCount: 5,
        observedDenominator: 5,
        observedNumerator: 3,
        observedValue: 6_000,
        secondary: null,
        severity: "critical",
        threshold: 5_000,
        windowSeconds: 300,
      },
      severity: "critical",
    });
  });

  it("keeps old current logout failures visible with empty recent cohorts", () => {
    const emptyWindows = windowed(
      { eligible: 0, leaseExpired: 0, unresolved: 0 },
    );
    expect(evaluateAlertRule({
      asOf: AS_OF,
      current: {
        currentDead: 1,
        currentUnresolved: 1,
        oldestUnresolvedAgeSeconds: 3_601,
      },
      dimension: GLOBAL,
      ruleId: "pgid.logout.delivery_health.v1",
      windows: emptyWindows,
    })).toMatchObject({
      immediateCritical: true,
      selectedEvidence: {
        metricName: "dead",
        observedValue: 1,
        windowSeconds: 300,
      },
      severity: "critical",
    });
    expect(evaluateAlertRule({
      asOf: AS_OF,
      current: {
        currentDead: 0,
        currentUnresolved: 1,
        oldestUnresolvedAgeSeconds: 3_601,
      },
      dimension: GLOBAL,
      ruleId: "pgid.logout.delivery_health.v1",
      windows: emptyWindows,
    })).toMatchObject({
      immediateCritical: false,
      selectedEvidence: {
        metricName: "oldest_unresolved_age_seconds",
        observedValue: 3_601,
        windowSeconds: 900,
      },
      severity: "critical",
    });
  });

  it("rejects invalid current logout subsets and non-nested window cohorts", () => {
    const base = {
      asOf: AS_OF,
      current: {
        currentDead: 0,
        currentUnresolved: 0,
        oldestUnresolvedAgeSeconds: null,
      },
      dimension: GLOBAL,
      ruleId: "pgid.logout.delivery_health.v1",
      windows: windowed({ eligible: 0, leaseExpired: 0, unresolved: 0 }),
    };
    expect(() => evaluateAlertRule({
      ...base,
      current: {
        currentDead: 2,
        currentUnresolved: 1,
        oldestUnresolvedAgeSeconds: 1,
      },
    })).toThrow("cannot exceed");
    expect(() => evaluateAlertRule({
      ...base,
      current: {
        currentDead: 0,
        currentUnresolved: 0,
        oldestUnresolvedAgeSeconds: 0,
      },
    })).toThrow("must agree");
    expect(() => evaluateAlertRule({
      ...base,
      current: {
        currentDead: 0,
        currentUnresolved: 1,
        oldestUnresolvedAgeSeconds: null,
      },
    })).toThrow("must agree");
    expect(() => evaluateAlertRule({
      ...base,
      windows: windowed({ eligible: 1, leaseExpired: 0, unresolved: 2 }),
    })).toThrow("cannot exceed");
    expect(() => evaluateAlertRule({
      ...base,
      windows: windowed(
        { eligible: 2, leaseExpired: 0, unresolved: 1 },
        { eligible: 1, leaseExpired: 0, unresolved: 1 },
        { eligible: 3, leaseExpired: 0, unresolved: 1 },
      ),
    })).toThrow("nondecreasing");
  });

  it("uses strict runtime ages and only exact dead/missing state is immediate", () => {
    expect(evaluateAlertRule(runtimeObservation(180, 120)).severity).toBe("none");
    expect(evaluateAlertRule(runtimeObservation(181, null))).toMatchObject({
      immediateCritical: false,
      severity: "warning",
    });
    expect(evaluateAlertRule(runtimeObservation(300, 300))).toMatchObject({
      immediateCritical: false,
      severity: "warning",
    });
    expect(evaluateAlertRule(runtimeObservation(301, null))).toMatchObject({
      immediateCritical: false,
      severity: "critical",
    });
    expect(evaluateAlertRule(runtimeObservation(null, null))).toMatchObject({
      immediateCritical: true,
      selectedEvidence: { metricName: "evaluator_missing" },
      severity: "critical",
    });
    expect(evaluateAlertRule(runtimeObservation(0, null, 1))).toMatchObject({
      immediateCritical: true,
      selectedEvidence: { metricName: "dead_outbox" },
      severity: "critical",
    });
  });

  it("selects the durable immediate cause ahead of a competing critical metric", () => {
    const logout = evaluateAlertRule({
      asOf: AS_OF,
      current: {
        currentDead: 1,
        currentUnresolved: 1,
        oldestUnresolvedAgeSeconds: 3_601,
      },
      dimension: GLOBAL,
      ruleId: "pgid.logout.delivery_health.v1",
      windows: windowed(
        {
          eligible: 5,
          leaseExpired: 0,
          unresolved: 3,
        },
        {
          eligible: 5,
          leaseExpired: 0,
          unresolved: 3,
        },
        {
          eligible: 5,
          leaseExpired: 0,
          unresolved: 3,
        },
      ),
    });
    expect(logout).toMatchObject({
      immediateCritical: true,
      selectedEvidence: {
        metricName: "dead",
        observedValue: 1,
        severity: "critical",
        windowSeconds: 300,
      },
    });

    const runtime = evaluateAlertRule(runtimeObservation(301, null, 1));
    expect(runtime).toMatchObject({
      immediateCritical: true,
      selectedEvidence: {
        metricName: "dead_outbox",
        severity: "critical",
        windowSeconds: 3_600,
      },
    });
  });

  it("evaluates fan-out as bounded snapshot counters", () => {
    const warning = evaluateAlertRule({
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.security.fanout_gap.v1",
      snapshot: { missingOlderThan15mCount: 0, missingOlderThan5mCount: 1 },
    });
    expect(warning).toMatchObject({
      selectedEvidence: {
        metricName: "missing",
        observedValue: 1,
        windowSeconds: 300,
      },
      severity: "warning",
    });
    expect(evaluateAlertRule({
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.security.fanout_gap.v1",
      snapshot: { missingOlderThan15mCount: 1, missingOlderThan5mCount: 1 },
    })).toMatchObject({
      selectedEvidence: {
        metricName: "missing",
        windowSeconds: 900,
      },
      severity: "critical",
    });
    expect(evaluateAlertRule({
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.security.fanout_gap.v1",
      snapshot: { missingOlderThan15mCount: 0, missingOlderThan5mCount: 10 },
    })).toMatchObject({
      selectedEvidence: {
        metricName: "missing",
        windowSeconds: 3_600,
      },
      severity: "critical",
    });
    expect(() => evaluateAlertRule({
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.security.fanout_gap.v1",
      snapshot: { missingOlderThan15mCount: 2, missingOlderThan5mCount: 1 },
    })).toThrow("inconsistent");
  });

  it("returns unknown for missing or inconsistent Queue samples", () => {
    const unknowns = [
      queueObservation({
        backlogBytes: null,
        backlogCount: null,
        consecutiveNonzeroSamples: null,
        nonzeroSinceAt: null,
        oldestMessageTimestamp: null,
        sampledAt: null,
      }),
      queueObservation({
        backlogBytes: 10,
        backlogCount: 1,
        consecutiveNonzeroSamples: 1,
        nonzeroSinceAt: AS_OF,
        oldestMessageTimestamp: "2026-07-17T11:58:00.000Z",
        sampledAt: "2026-07-17T11:59:00.000Z",
      }),
      queueObservation({
        backlogBytes: 10,
        backlogCount: 1,
        consecutiveNonzeroSamples: 999,
        nonzeroSinceAt: "2026-07-17T11:45:00.000Z",
        oldestMessageTimestamp: "2026-07-17T11:44:00.000Z",
        sampledAt: AS_OF,
      }),
      queueObservation({
        backlogBytes: 0,
        backlogCount: 0,
        consecutiveNonzeroSamples: 1,
        nonzeroSinceAt: AS_OF,
        oldestMessageTimestamp: null,
        sampledAt: AS_OF,
      }),
    ];
    for (const observation of unknowns) {
      expect(evaluateAlertRule(observation)).toMatchObject({
        evidence: "unknown",
        selectedEvidence: null,
        severity: "none",
      });
    }
  });

  it("validates every Queue metrics field before using persisted streak state", () => {
    const queueMetricsUnknown = (overrides: Record<string, unknown>) =>
      queueObservation({
        backlogBytes: 10,
        backlogCount: 1,
        consecutiveNonzeroSamples: 1,
        nonzeroSinceAt: AS_OF,
        oldestMessageTimestamp: AS_OF,
        sampledAt: AS_OF,
        ...overrides,
      });
    const unknowns = [
      queueMetricsUnknown({ backlogCount: -1 }),
      queueMetricsUnknown({ backlogBytes: Number.NaN }),
      queueMetricsUnknown({ backlogCount: Number.POSITIVE_INFINITY }),
      queueMetricsUnknown({ backlogCount: 1_000_000_001 }),
      queueMetricsUnknown({ backlogBytes: 1_000_000_000_001 }),
      queueMetricsUnknown({ oldestMessageTimestamp: "not-a-timestamp" }),
      queueMetricsUnknown({ oldestMessageTimestamp: "2026-07-17T12:00:01.000Z" }),
      queueMetricsUnknown({ oldestMessageTimestamp: "1990-01-01T00:00:00.000Z" }),
      queueObservation({
        backlogBytes: 10,
        backlogCount: 1,
        consecutiveNonzeroSamples: 1,
        nonzeroSinceAt: AS_OF,
        sampledAt: AS_OF,
      }),
    ];
    for (const observation of unknowns) {
      expect(evaluateAlertRule(observation)).toMatchObject({
        evidence: "unknown",
        selectedEvidence: null,
        severity: "none",
      });
    }

    const dateInput = queueMetricsUnknown({
      oldestMessageTimestamp: new Date(AS_OF),
    });
    expect(parseAlertObservation(dateInput)).toMatchObject({
      snapshot: { oldestMessageTimestamp: AS_OF },
    });
    expect(evaluateAlertRule(dateInput)).toMatchObject({
      evidence: "known",
      severity: "warning",
    });

    expect(() => evaluateAlertRule(queueMetricsUnknown({
      consecutiveNonzeroSamples: 1_000_001,
    }))).toThrow("persistence domain");
    expect(parseAlertObservation(queueMetricsUnknown({
      consecutiveNonzeroSamples: 1_000_000,
    }))).toMatchObject({
      snapshot: { consecutiveNonzeroSamples: 1_000_000 },
    });
  });

  it("requires both Queue streak and duration for duration critical", () => {
    const short = evaluateAlertRule(queueObservation({
      backlogBytes: 10,
      backlogCount: 1,
      consecutiveNonzeroSamples: 15,
      nonzeroSinceAt: "2026-07-17T11:45:01.000Z",
      oldestMessageTimestamp: "2026-07-17T11:44:00.000Z",
      sampledAt: AS_OF,
    }));
    expect(short.severity).toBe("warning");

    const duration = evaluateAlertRule(queueObservation({
      backlogBytes: 10,
      backlogCount: 1,
      consecutiveNonzeroSamples: 15,
      nonzeroSinceAt: "2026-07-17T11:45:00.000Z",
      oldestMessageTimestamp: "2026-07-17T11:44:00.000Z",
      sampledAt: AS_OF,
    }));
    expect(duration).toMatchObject({
      immediateCritical: false,
      selectedEvidence: {
        metricName: "consecutive_nonzero_samples",
        observedValue: 15,
        secondary: null,
        windowSeconds: 900,
      },
      severity: "critical",
    });

    expect(evaluateAlertRule(queueObservation({
      backlogBytes: 100,
      backlogCount: 10,
      consecutiveNonzeroSamples: 1,
      nonzeroSinceAt: AS_OF,
      oldestMessageTimestamp: AS_OF,
      sampledAt: AS_OF,
    }))).toMatchObject({
      selectedEvidence: { metricName: "depth", secondary: null },
      severity: "critical",
    });
  });

  it("retains exactly one secondary component for compound evidence", () => {
    const restricted = evaluateAlertRule({
      asOf: AS_OF,
      dimension: SUBJECT,
      ruleId: "pgid.restricted.sensitive_denied.v1",
      windows: windowed(
        { count: 0, knownSurfaces: 0 },
        { count: 0, knownSurfaces: 0 },
        { count: 5, knownSurfaces: 2 },
      ),
    });
    expect(restricted.selectedEvidence).toMatchObject({
      metricName: "count",
      secondary: { metricName: "known_surfaces", observedValue: 2, threshold: 2 },
      severity: "critical",
    });

    const oauth = evaluateAlertRule({
      asOf: AS_OF,
      dimension: CLIENT,
      ruleId: "pgid.oauth.client_report.v1",
      windows: windowed(
        { count: 0, distinctReporters: 0, highRiskCount: 0 },
        { count: 0, distinctReporters: 0, highRiskCount: 0 },
        { count: 3, distinctReporters: 2, highRiskCount: 3 },
      ),
    });
    expect(oauth.selectedEvidence).toMatchObject({
      metricName: "high_risk_count",
      secondary: { metricName: "distinct_reporters", observedValue: 2, threshold: 2 },
      severity: "critical",
    });
  });

  it("preserves exact OAuth branches when reporter coverage is partial", () => {
    const totalCritical = evaluateAlertRule({
      asOf: AS_OF,
      dimension: CLIENT,
      ruleId: "pgid.oauth.client_report.v1",
      windows: windowed(
        { count: 0, distinctReporters: 0, highRiskCount: 0 },
        { count: 0, distinctReporters: 0, highRiskCount: 0 },
        { count: 10, distinctReporters: null, highRiskCount: 3 },
      ),
    });
    expect(totalCritical).toMatchObject({
      evidence: "known",
      selectedEvidence: {
        metricName: "count",
        observedValue: 10,
        severity: "critical",
        threshold: 10,
        windowSeconds: 3_600,
      },
      severity: "critical",
    });

    const warning = evaluateAlertRule({
      asOf: AS_OF,
      dimension: CLIENT,
      ruleId: "pgid.oauth.client_report.v1",
      windows: windowed(
        { count: 1, distinctReporters: 1, highRiskCount: 1 },
        { count: 1, distinctReporters: 1, highRiskCount: 1 },
        { count: 3, distinctReporters: null, highRiskCount: 3 },
      ),
    });
    expect(warning).toMatchObject({
      evidence: "known",
      selectedEvidence: {
        metricName: "high_risk_count",
        severity: "warning",
        windowSeconds: 300,
      },
      severity: "warning",
    });

    const unknown = evaluateAlertRule({
      asOf: AS_OF,
      dimension: CLIENT,
      ruleId: "pgid.oauth.client_report.v1",
      windows: windowed(
        { count: 0, distinctReporters: 0, highRiskCount: 0 },
        { count: 0, distinctReporters: 0, highRiskCount: 0 },
        { count: 3, distinctReporters: null, highRiskCount: 3 },
      ),
    });
    expect(unknown).toEqual({
      asOf: AS_OF,
      breachedWindows: [],
      dimension: CLIENT,
      evidence: "unknown",
      immediateCritical: false,
      ruleId: "pgid.oauth.client_report.v1",
      selectedEvidence: null,
      severity: "none",
    });

    const clear = evaluateAlertRule({
      asOf: AS_OF,
      dimension: CLIENT,
      ruleId: "pgid.oauth.client_report.v1",
      windows: windowed(
        { count: 0, distinctReporters: 0, highRiskCount: 0 },
        { count: 0, distinctReporters: 0, highRiskCount: 0 },
        { count: 1, distinctReporters: null, highRiskCount: 0 },
      ),
    });
    expect(clear).toMatchObject({
      evidence: "known",
      selectedEvidence: null,
      severity: "none",
    });
  });

  it("emits only all-present schema-shaped evidence", () => {
    const evaluation = evaluateAlertRule({
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.registration.challenge_unavailable.v1",
      windows: windowed(
        { denominator: 5, numerator: 2 },
        { denominator: 5, numerator: 2 },
        { denominator: 5, numerator: 2 },
      ),
    });
    expect(evaluation.selectedEvidence).toEqual({
      kind: "ratio",
      metricName: "ratio",
      minimumNumeratorCount: 2,
      minimumSampleCount: 5,
      observedDenominator: 5,
      observedNumerator: 2,
      observedValue: 4_000,
      secondary: null,
      severity: "warning",
      threshold: 2_000,
      unit: "basis_points",
      windowSeconds: 300,
    });
    expect(Object.keys(evaluation.selectedEvidence ?? {})).not.toContain("provenance");
    expect(Object.keys(evaluation.selectedEvidence ?? {})).not.toContain("components");
    expect(parseAlertSelectedEvidence(evaluation.selectedEvidence))
      .toEqual(evaluation.selectedEvidence);
  });

  it("enforces exact persistence caps and subset limits", () => {
    expect(() => evaluateAlertRule({
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.registration.denied.v1",
      windows: windowed({ count: 1_000_000_001 }),
    })).toThrow("persistence domain");
    expect(() => evaluateAlertRule({
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.registration.challenge_unavailable.v1",
      windows: windowed({ denominator: 1_000_001, numerator: 1_000_001 }),
    })).toThrow("persistence domain");
    expect(() => evaluateAlertRule({
      asOf: AS_OF,
      dimension: SUBJECT,
      ruleId: "pgid.restricted.sensitive_denied.v1",
      windows: windowed({ count: 8, knownSurfaces: 8 }),
    })).toThrow("canonical denied-event domain");

    const maximum = evaluateAlertRule({
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.registration.denied.v1",
      windows: windowed({ count: 1_000_000_000 }),
    });
    expect(maximum.selectedEvidence?.observedValue).toBe(1_000_000_000);
  });

  it("rejects malformed persisted evidence rather than coercing it", () => {
    const valid = evaluateAlertRule({
      asOf: AS_OF,
      dimension: ACTOR,
      ruleId: "pgid.admin.sensitive_activity.v1",
      windows: windowed({ protectedDenials: 0, successes: 1 }),
    }).selectedEvidence;
    expect(valid).not.toBeNull();
    expect(() => parseAlertSelectedEvidence({ ...valid, raw: "redacted" }))
      .toThrow("canonical keys");
    expect(() => parseAlertSelectedEvidence({
      ...valid,
      observedValue: 1_000_000_001,
    })).toThrow("persistence domain");
    expect(() => parseAlertSelectedEvidence({
      ...valid,
      observedValue: 0,
    })).toThrow("canonical breach");
    expect(() => parseAlertSelectedEvidence({
      ...valid,
      kind: "age_seconds",
      metricName: "nonzero_duration_seconds",
      unit: "seconds",
    })).toThrow("metric name");
  });

  it("is deterministic and does not mutate the observation", () => {
    const observation = {
      asOf: AS_OF,
      dimension: SUBJECT,
      ruleId: "pgid.restricted.sensitive_denied.v1",
      windows: windowed(
        { count: 3, knownSurfaces: 1 },
        { count: 3, knownSurfaces: 1 },
        { count: 3, knownSurfaces: 1 },
      ),
    };
    const snapshot = structuredClone(observation);
    expect(evaluateAlertRule(observation)).toEqual(evaluateAlertRule(observation));
    expect(observation).toEqual(snapshot);
  });
});

describe("closed rule id typing", () => {
  it("keeps definition IDs exact", () => {
    const ids: readonly AlertRuleId[] = ALERT_RULE_IDS;
    for (const id of ids) expect(ALERT_RULE_DEFINITIONS[id].id).toBe(id);
  });
});
