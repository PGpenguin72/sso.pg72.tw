export const ALERT_RULE_IDS = [
  "pgid.registration.rate_limited.v1",
  "pgid.registration.denied.v1",
  "pgid.registration.challenge_unavailable.v1",
  "pgid.registration.restricted_created.v1",
  "pgid.restricted.sensitive_denied.v1",
  "pgid.recovery.entry_abuse.v1",
  "pgid.recovery.passkey_failure.v1",
  "pgid.passkey.step_up_failure.v1",
  "pgid.oauth.client_report.v1",
  "pgid.admin.sensitive_activity.v1",
  "pgid.admin.directory_volume.v1",
  "pgid.security.fanout_gap.v1",
  "pgid.logout.delivery_health.v1",
  "pgid.alert.runtime_health.v1",
  "pgid.queue.dlq_approximate.v1",
] as const;

export type AlertRuleId = (typeof ALERT_RULE_IDS)[number];
export type AlertSeverity = "none" | "warning" | "critical";
export type AlertEvidenceStatus = "known" | "unknown";
export type AlertProvenance = "d1_exact" | "queue_approximate";
export type AlertWindowKey = "5m" | "15m" | "60m";

export const ALERT_WINDOW_KEYS = ["5m", "15m", "60m"] as const;
/** Severity wins first, then the shortest window, then expression declaration order. */
export const ALERT_EVIDENCE_WINDOW_ORDER = ALERT_WINDOW_KEYS;

const WINDOW_MINUTES: Readonly<Record<AlertWindowKey, number>> = {
  "5m": 5,
  "15m": 15,
  "60m": 60,
};

const HMAC_REFERENCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface HashedAlertReference {
  keyVersion: 1;
  value: string;
}

export type AlertQueueName =
  | "security_events_dlq"
  | "logout_deliveries_dlq"
  | "alert_deliveries_dlq"
  | "audit_archive_dlq";

export type AlertDimension =
  | { kind: "global" }
  | { kind: "subject_hmac"; reference: HashedAlertReference }
  | { kind: "actor_hmac"; reference: HashedAlertReference }
  | { kind: "client_hmac"; reference: HashedAlertReference }
  | { kind: "queue"; queue: AlertQueueName };

export type HashedAlertDimension = Extract<
  AlertDimension,
  { kind: "actor_hmac" | "client_hmac" | "subject_hmac" }
>;

export interface AlertWindowDescriptor {
  endExclusive: string;
  key: AlertWindowKey;
  minutes: number;
  startInclusive: string;
}

export function isHashedAlertReference(
  value: unknown,
): value is HashedAlertReference {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const record = value as { keyVersion?: unknown; value?: unknown };
  return (
    typeof record.keyVersion === "number" &&
    Number.isSafeInteger(record.keyVersion) &&
    record.keyVersion === 1 &&
    typeof record.value === "string" &&
    HMAC_REFERENCE_PATTERN.test(record.value)
  );
}

export function alertWindowsAt(asOf: string): readonly AlertWindowDescriptor[] {
  const timestamp = new Date(asOf).getTime();
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== asOf) {
    throw new Error("asOf must be a canonical UTC ISO timestamp");
  }
  return ALERT_WINDOW_KEYS.map((key) => ({
    endExclusive: asOf,
    key,
    minutes: WINDOW_MINUTES[key],
    startInclusive: new Date(
      timestamp - WINDOW_MINUTES[key] * 60_000,
    ).toISOString(),
  }));
}

export type AlertMetricName =
  | "count"
  | "dead"
  | "deadOutbox"
  | "denominator"
  | "depth"
  | "distinctReporters"
  | "evaluatorAgeSeconds"
  | "evaluatorMissing"
  | "highRiskCount"
  | "knownSurfaces"
  | "leaseExpired"
  | "missing"
  | "nonzeroMinutes"
  | "numerator"
  | "oldestMissingAgeSeconds"
  | "oldestUnresolvedAgeSeconds"
  | "outboxDueAgeSeconds"
  | "protectedDenials"
  | "rateLimited"
  | "successes";

type ThresholdExpression =
  | { metric: AlertMetricName; op: "gte"; value: number }
  | {
      basisPoints: number;
      denominator: AlertMetricName;
      minDenominator: number;
      minNumerator: number;
      numerator: AlertMetricName;
      op: "ratio_gte";
    }
  | { clauses: readonly ThresholdExpression[]; op: "all" | "any" };

interface WindowThresholdDefinition {
  critical: ThresholdExpression | null;
  warning: ThresholdExpression | null;
}

export interface AlertRuleDefinition {
  dimensions: readonly AlertDimension["kind"][];
  id: AlertRuleId;
  provenance: AlertProvenance;
  thresholds: Readonly<Record<AlertWindowKey, WindowThresholdDefinition>>;
}

const countAtLeast = (
  metric: AlertMetricName,
  value: number,
): ThresholdExpression => ({ metric, op: "gte", value });

const ratioAtLeast = (
  minDenominator: number,
  minNumerator: number,
  basisPoints: number,
): ThresholdExpression => ({
  basisPoints,
  denominator: "denominator",
  minDenominator,
  minNumerator,
  numerator: "numerator",
  op: "ratio_gte",
});

const anyOf = (...clauses: readonly ThresholdExpression[]): ThresholdExpression => ({
  clauses,
  op: "any",
});

const allOf = (...clauses: readonly ThresholdExpression[]): ThresholdExpression => ({
  clauses,
  op: "all",
});

export const ALERT_RULE_DEFINITIONS = {
  "pgid.registration.rate_limited.v1": {
    dimensions: ["global"],
    id: "pgid.registration.rate_limited.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": { critical: null, warning: countAtLeast("count", 5) },
      "15m": { critical: null, warning: countAtLeast("count", 10) },
      "60m": { critical: countAtLeast("count", 40), warning: null },
    },
  },
  "pgid.registration.denied.v1": {
    dimensions: ["global"],
    id: "pgid.registration.denied.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": { critical: null, warning: countAtLeast("count", 10) },
      "15m": { critical: null, warning: countAtLeast("count", 25) },
      "60m": { critical: countAtLeast("count", 100), warning: null },
    },
  },
  "pgid.registration.challenge_unavailable.v1": {
    dimensions: ["global"],
    id: "pgid.registration.challenge_unavailable.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": { critical: null, warning: ratioAtLeast(5, 2, 2_000) },
      "15m": { critical: null, warning: ratioAtLeast(15, 2, 2_000) },
      "60m": {
        critical: ratioAtLeast(30, 5, 5_000),
        warning: ratioAtLeast(30, 2, 2_000),
      },
    },
  },
  "pgid.registration.restricted_created.v1": {
    dimensions: ["global"],
    id: "pgid.registration.restricted_created.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": { critical: null, warning: countAtLeast("count", 7) },
      "15m": { critical: null, warning: countAtLeast("count", 20) },
      "60m": { critical: countAtLeast("count", 80), warning: null },
    },
  },
  "pgid.restricted.sensitive_denied.v1": {
    dimensions: ["subject_hmac"],
    id: "pgid.restricted.sensitive_denied.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": { critical: null, warning: countAtLeast("count", 3) },
      "15m": { critical: null, warning: countAtLeast("count", 5) },
      "60m": {
        critical: anyOf(
          countAtLeast("count", 20),
          allOf(
            countAtLeast("count", 5),
            countAtLeast("knownSurfaces", 2),
          ),
        ),
        warning: countAtLeast("count", 5),
      },
    },
  },
  "pgid.recovery.entry_abuse.v1": {
    dimensions: ["global"],
    id: "pgid.recovery.entry_abuse.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": {
        critical: null,
        warning: anyOf(
          countAtLeast("rateLimited", 5),
          ratioAtLeast(5, 5, 8_000),
        ),
      },
      "15m": {
        critical: null,
        warning: anyOf(
          countAtLeast("rateLimited", 10),
          ratioAtLeast(15, 10, 8_000),
        ),
      },
      "60m": {
        critical: anyOf(
          countAtLeast("rateLimited", 40),
          ratioAtLeast(30, 40, 9_000),
        ),
        warning: null,
      },
    },
  },
  "pgid.recovery.passkey_failure.v1": {
    dimensions: ["global", "subject_hmac"],
    id: "pgid.recovery.passkey_failure.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": { critical: null, warning: ratioAtLeast(3, 3, 6_000) },
      "15m": { critical: null, warning: ratioAtLeast(5, 5, 6_000) },
      "60m": {
        critical: ratioAtLeast(10, 10, 8_000),
        warning: ratioAtLeast(10, 5, 6_000),
      },
    },
  },
  "pgid.passkey.step_up_failure.v1": {
    dimensions: ["global", "subject_hmac"],
    id: "pgid.passkey.step_up_failure.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": { critical: null, warning: ratioAtLeast(5, 3, 3_000) },
      "15m": { critical: null, warning: ratioAtLeast(15, 5, 3_000) },
      "60m": {
        critical: ratioAtLeast(30, 10, 6_000),
        warning: ratioAtLeast(30, 5, 3_000),
      },
    },
  },
  "pgid.oauth.client_report.v1": {
    dimensions: ["client_hmac"],
    id: "pgid.oauth.client_report.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": { critical: null, warning: countAtLeast("highRiskCount", 1) },
      "15m": { critical: null, warning: countAtLeast("count", 3) },
      "60m": {
        critical: anyOf(
          allOf(
            countAtLeast("highRiskCount", 3),
            countAtLeast("distinctReporters", 2),
          ),
          countAtLeast("count", 10),
        ),
        warning: countAtLeast("count", 3),
      },
    },
  },
  "pgid.admin.sensitive_activity.v1": {
    dimensions: ["actor_hmac"],
    id: "pgid.admin.sensitive_activity.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": {
        critical: null,
        warning: anyOf(
          countAtLeast("successes", 1),
          countAtLeast("protectedDenials", 1),
        ),
      },
      "15m": { critical: countAtLeast("count", 3), warning: null },
      "60m": { critical: countAtLeast("count", 10), warning: null },
    },
  },
  "pgid.admin.directory_volume.v1": {
    dimensions: ["actor_hmac"],
    id: "pgid.admin.directory_volume.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": { critical: null, warning: countAtLeast("count", 20) },
      "15m": { critical: null, warning: countAtLeast("count", 50) },
      "60m": { critical: countAtLeast("count", 200), warning: null },
    },
  },
  "pgid.security.fanout_gap.v1": {
    dimensions: ["global"],
    id: "pgid.security.fanout_gap.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": {
        critical: null,
        warning: countAtLeast("oldestMissingAgeSeconds", 5 * 60),
      },
      "15m": {
        critical: countAtLeast("oldestMissingAgeSeconds", 15 * 60),
        warning: null,
      },
      "60m": { critical: countAtLeast("missing", 10), warning: null },
    },
  },
  "pgid.logout.delivery_health.v1": {
    dimensions: ["global", "client_hmac"],
    id: "pgid.logout.delivery_health.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": {
        critical: countAtLeast("dead", 1),
        warning: anyOf(
          countAtLeast("oldestUnresolvedAgeSeconds", 2 * 60),
          countAtLeast("leaseExpired", 1),
          ratioAtLeast(5, 1, 2_000),
        ),
      },
      "15m": {
        critical: anyOf(
          countAtLeast("dead", 1),
          countAtLeast("oldestUnresolvedAgeSeconds", 5 * 60),
          countAtLeast("leaseExpired", 3),
          ratioAtLeast(10, 1, 5_000),
        ),
        warning: ratioAtLeast(10, 1, 2_000),
      },
      "60m": {
        critical: anyOf(
          countAtLeast("dead", 1),
          countAtLeast("leaseExpired", 5),
          ratioAtLeast(20, 1, 5_000),
        ),
        warning: ratioAtLeast(20, 1, 2_000),
      },
    },
  },
  "pgid.alert.runtime_health.v1": {
    dimensions: ["global"],
    id: "pgid.alert.runtime_health.v1",
    provenance: "d1_exact",
    thresholds: {
      "5m": {
        critical: null,
        warning: anyOf(
          countAtLeast("evaluatorAgeSeconds", 3 * 60),
          countAtLeast("outboxDueAgeSeconds", 2 * 60),
        ),
      },
      "15m": {
        critical: anyOf(
          countAtLeast("evaluatorMissing", 1),
          countAtLeast("evaluatorAgeSeconds", 5 * 60),
          countAtLeast("outboxDueAgeSeconds", 5 * 60),
        ),
        warning: null,
      },
      "60m": {
        critical: countAtLeast("deadOutbox", 1),
        warning: null,
      },
    },
  },
  "pgid.queue.dlq_approximate.v1": {
    dimensions: ["queue"],
    id: "pgid.queue.dlq_approximate.v1",
    provenance: "queue_approximate",
    thresholds: {
      "5m": { critical: null, warning: countAtLeast("depth", 1) },
      "15m": {
        critical: anyOf(
          countAtLeast("depth", 10),
          countAtLeast("nonzeroMinutes", 15),
        ),
        warning: null,
      },
      "60m": {
        critical: anyOf(
          countAtLeast("depth", 10),
          countAtLeast("nonzeroMinutes", 15),
        ),
        warning: null,
      },
    },
  },
} as const satisfies Record<AlertRuleId, AlertRuleDefinition>;

export interface AlertRulePolicy {
  clearConsecutive: 5;
  cooldownMs: number;
  criticalConsecutive: 2;
  criticalReminderMs: number;
  warningConsecutive: 2;
  warningReminderMs: number;
}

export const ALERT_RULE_POLICY: AlertRulePolicy = {
  clearConsecutive: 5,
  cooldownMs: 30 * 60_000,
  criticalConsecutive: 2,
  criticalReminderMs: 15 * 60_000,
  warningConsecutive: 2,
  warningReminderMs: 60 * 60_000,
};

export type Windowed<T> = Readonly<Record<AlertWindowKey, T>>;

interface ObservationBase<
  RuleId extends AlertRuleId,
  Dimension extends AlertDimension,
  Metrics,
> {
  asOf: string;
  dimension: Dimension;
  ruleId: RuleId;
  windows: Windowed<Metrics>;
}

export interface CountWindowMetrics {
  count: number;
}

export interface RatioWindowMetrics {
  denominator: number;
  numerator: number;
}

export interface RestrictedDenialWindowMetrics {
  count: number;
  knownSurfaces: number;
}

export interface RecoveryEntryWindowMetrics {
  denied: number;
  rateLimited: number;
  started: number;
}

export interface OAuthClientReportWindowMetrics {
  count: number;
  distinctReporters: number;
  highRiskCount: number;
}

export interface AdminSensitiveWindowMetrics {
  protectedDenials: number;
  successes: number;
}

export interface FanoutGapWindowMetrics {
  missing: number;
  oldestMissingAgeSeconds: number | null;
}

export interface LogoutDeliveryWindowMetrics {
  dead: number;
  eligible: number;
  leaseExpired: number;
  oldestUnresolvedAgeSeconds: number | null;
  unresolved: number;
}

export interface AlertRuntimeWindowMetrics {
  deadOutbox: number;
  evaluatorAgeSeconds: number | null;
  outboxDueAgeSeconds: number | null;
}

export interface QueueDepthWindowMetrics {
  depth: number | null;
  nonzeroMinutes: number;
}

type GlobalCountRuleId =
  | "pgid.registration.rate_limited.v1"
  | "pgid.registration.denied.v1"
  | "pgid.registration.restricted_created.v1";

export type AlertRuleObservation =
  | ObservationBase<GlobalCountRuleId, { kind: "global" }, CountWindowMetrics>
  | ObservationBase<
      "pgid.registration.challenge_unavailable.v1",
      { kind: "global" },
      RatioWindowMetrics
    >
  | ObservationBase<
      "pgid.restricted.sensitive_denied.v1",
      Extract<AlertDimension, { kind: "subject_hmac" }>,
      RestrictedDenialWindowMetrics
    >
  | ObservationBase<
      "pgid.recovery.entry_abuse.v1",
      { kind: "global" },
      RecoveryEntryWindowMetrics
    >
  | ObservationBase<
      | "pgid.recovery.passkey_failure.v1"
      | "pgid.passkey.step_up_failure.v1",
      { kind: "global" } | Extract<AlertDimension, { kind: "subject_hmac" }>,
      RatioWindowMetrics
    >
  | ObservationBase<
      "pgid.oauth.client_report.v1",
      Extract<AlertDimension, { kind: "client_hmac" }>,
      OAuthClientReportWindowMetrics
    >
  | ObservationBase<
      "pgid.admin.sensitive_activity.v1",
      Extract<AlertDimension, { kind: "actor_hmac" }>,
      AdminSensitiveWindowMetrics
    >
  | ObservationBase<
      "pgid.admin.directory_volume.v1",
      Extract<AlertDimension, { kind: "actor_hmac" }>,
      CountWindowMetrics
    >
  | ObservationBase<
      "pgid.security.fanout_gap.v1",
      { kind: "global" },
      FanoutGapWindowMetrics
    >
  | ObservationBase<
      "pgid.logout.delivery_health.v1",
      { kind: "global" } | Extract<AlertDimension, { kind: "client_hmac" }>,
      LogoutDeliveryWindowMetrics
    >
  | ObservationBase<
      "pgid.alert.runtime_health.v1",
      { kind: "global" },
      AlertRuntimeWindowMetrics
    >
  | ObservationBase<
      "pgid.queue.dlq_approximate.v1",
      Extract<AlertDimension, { kind: "queue" }>,
      QueueDepthWindowMetrics
    >;

interface MetricBag {
  count?: number;
  dead?: number;
  deadOutbox?: number;
  denominator?: number;
  depth?: number;
  distinctReporters?: number;
  evaluatorAgeSeconds?: number;
  evaluatorMissing?: number;
  highRiskCount?: number;
  knownSurfaces?: number;
  leaseExpired?: number;
  missing?: number;
  nonzeroMinutes?: number;
  numerator?: number;
  oldestMissingAgeSeconds?: number;
  oldestUnresolvedAgeSeconds?: number;
  outboxDueAgeSeconds?: number;
  protectedDenials?: number;
  rateLimited?: number;
  successes?: number;
}

export interface AlertRuleEvaluation {
  asOf: string;
  breachedWindows: readonly AlertWindowKey[];
  dimension: AlertDimension;
  evidence: AlertEvidenceStatus;
  immediateCritical: boolean;
  ruleId: AlertRuleId;
  selectedEvidence: AlertSelectedEvidence | null;
  severity: AlertSeverity;
}

export type AlertEvidenceMetricKind =
  | "age_seconds"
  | "boolean"
  | "consecutive"
  | "count"
  | "ratio";
export type AlertEvidenceUnit =
  | "basis_points"
  | "events"
  | "samples"
  | "seconds"
  | "state";

export interface AlertMetricEvidence {
  denominator?: number;
  kind: AlertEvidenceMetricKind;
  metric: AlertMetricName | "ratio";
  minNumerator?: number;
  minSample?: number;
  numerator?: number;
  threshold: number;
  unit: AlertEvidenceUnit;
  value: number;
}

export interface AlertSelectedEvidence extends AlertMetricEvidence {
  components: readonly AlertMetricEvidence[];
  provenance: AlertProvenance;
  severity: Exclude<AlertSeverity, "none">;
  window: AlertWindowKey;
}

function assertNonNegativeInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
}

function assertNullableAge(value: number | null, name: string): void {
  if (value !== null) assertNonNegativeInteger(value, name);
}

function assertDimension(dimension: AlertDimension, ruleId: AlertRuleId): void {
  const definition = ALERT_RULE_DEFINITIONS[ruleId];
  if (!definition.dimensions.some((allowed) => allowed === dimension.kind)) {
    throw new Error(`dimension ${dimension.kind} is not allowed for ${ruleId}`);
  }
  if (
    (dimension.kind === "actor_hmac" ||
      dimension.kind === "client_hmac" ||
      dimension.kind === "subject_hmac") &&
    !isHashedAlertReference(dimension.reference)
  ) {
    throw new Error("alert identity dimensions require a versioned HMAC reference");
  }
}

function countMetrics(metrics: CountWindowMetrics): MetricBag {
  assertNonNegativeInteger(metrics.count, "count");
  return { count: metrics.count };
}

function ratioMetrics(metrics: RatioWindowMetrics): MetricBag {
  assertNonNegativeInteger(metrics.numerator, "numerator");
  assertNonNegativeInteger(metrics.denominator, "denominator");
  if (metrics.numerator > metrics.denominator) {
    throw new Error("numerator cannot exceed denominator");
  }
  return metrics;
}

function metricsForObservation(
  observation: AlertRuleObservation,
): Windowed<MetricBag> {
  const mapped = {} as Record<AlertWindowKey, MetricBag>;
  for (const window of ALERT_WINDOW_KEYS) {
    switch (observation.ruleId) {
      case "pgid.registration.rate_limited.v1":
      case "pgid.registration.denied.v1":
      case "pgid.registration.restricted_created.v1":
      case "pgid.admin.directory_volume.v1":
        mapped[window] = countMetrics(observation.windows[window]);
        break;
      case "pgid.registration.challenge_unavailable.v1":
      case "pgid.recovery.passkey_failure.v1":
      case "pgid.passkey.step_up_failure.v1":
        mapped[window] = ratioMetrics(observation.windows[window]);
        break;
      case "pgid.restricted.sensitive_denied.v1": {
        const metrics = observation.windows[window];
        assertNonNegativeInteger(metrics.count, "count");
        assertNonNegativeInteger(metrics.knownSurfaces, "knownSurfaces");
        if (metrics.knownSurfaces > metrics.count) {
          throw new Error("known surfaces cannot exceed denied events");
        }
        mapped[window] = metrics;
        break;
      }
      case "pgid.recovery.entry_abuse.v1": {
        const metrics = observation.windows[window];
        assertNonNegativeInteger(metrics.denied, "denied");
        assertNonNegativeInteger(metrics.rateLimited, "rateLimited");
        assertNonNegativeInteger(metrics.started, "started");
        const denominator = metrics.denied + metrics.started;
        if (!Number.isSafeInteger(denominator)) {
          throw new Error("recovery denominator exceeds the safe integer range");
        }
        mapped[window] = {
          denominator,
          numerator: metrics.denied,
          rateLimited: metrics.rateLimited,
        };
        break;
      }
      case "pgid.oauth.client_report.v1": {
        const metrics = observation.windows[window];
        assertNonNegativeInteger(metrics.count, "count");
        assertNonNegativeInteger(metrics.distinctReporters, "distinctReporters");
        assertNonNegativeInteger(metrics.highRiskCount, "highRiskCount");
        if (
          metrics.distinctReporters > metrics.count ||
          metrics.highRiskCount > metrics.count
        ) {
          throw new Error("OAuth report subsets cannot exceed total reports");
        }
        mapped[window] = metrics;
        break;
      }
      case "pgid.admin.sensitive_activity.v1": {
        const metrics = observation.windows[window];
        assertNonNegativeInteger(metrics.successes, "successes");
        assertNonNegativeInteger(metrics.protectedDenials, "protectedDenials");
        const count = metrics.successes + metrics.protectedDenials;
        if (!Number.isSafeInteger(count)) {
          throw new Error("admin activity count exceeds the safe integer range");
        }
        mapped[window] = { ...metrics, count };
        break;
      }
      case "pgid.security.fanout_gap.v1": {
        const metrics = observation.windows[window];
        assertNonNegativeInteger(metrics.missing, "missing");
        assertNullableAge(
          metrics.oldestMissingAgeSeconds,
          "oldestMissingAgeSeconds",
        );
        if (
          (metrics.missing === 0) !==
          (metrics.oldestMissingAgeSeconds === null)
        ) {
          throw new Error("fan-out missing count and oldest age must agree");
        }
        mapped[window] = {
          missing: metrics.missing,
          ...(metrics.oldestMissingAgeSeconds === null
            ? {}
            : { oldestMissingAgeSeconds: metrics.oldestMissingAgeSeconds }),
        };
        break;
      }
      case "pgid.logout.delivery_health.v1": {
        const metrics = observation.windows[window];
        assertNonNegativeInteger(metrics.dead, "dead");
        assertNonNegativeInteger(metrics.eligible, "eligible");
        assertNonNegativeInteger(metrics.leaseExpired, "leaseExpired");
        assertNonNegativeInteger(metrics.unresolved, "unresolved");
        assertNullableAge(
          metrics.oldestUnresolvedAgeSeconds,
          "oldestUnresolvedAgeSeconds",
        );
        if (metrics.unresolved > metrics.eligible || metrics.dead > metrics.unresolved) {
          throw new Error("logout delivery subsets cannot exceed their cohort");
        }
        if (
          (metrics.unresolved === 0) !==
          (metrics.oldestUnresolvedAgeSeconds === null)
        ) {
          throw new Error("logout unresolved count and oldest age must agree");
        }
        mapped[window] = {
          dead: metrics.dead,
          denominator: metrics.eligible,
          leaseExpired: metrics.leaseExpired,
          numerator: metrics.unresolved,
          ...(metrics.oldestUnresolvedAgeSeconds === null
            ? {}
            : {
                oldestUnresolvedAgeSeconds:
                  metrics.oldestUnresolvedAgeSeconds,
              }),
        };
        break;
      }
      case "pgid.alert.runtime_health.v1": {
        const metrics = observation.windows[window];
        assertNonNegativeInteger(metrics.deadOutbox, "deadOutbox");
        assertNullableAge(metrics.evaluatorAgeSeconds, "evaluatorAgeSeconds");
        assertNullableAge(metrics.outboxDueAgeSeconds, "outboxDueAgeSeconds");
        mapped[window] = {
          deadOutbox: metrics.deadOutbox,
          evaluatorMissing: metrics.evaluatorAgeSeconds === null ? 1 : 0,
          ...(metrics.evaluatorAgeSeconds === null
            ? {}
            : { evaluatorAgeSeconds: metrics.evaluatorAgeSeconds }),
          ...(metrics.outboxDueAgeSeconds === null
            ? {}
            : { outboxDueAgeSeconds: metrics.outboxDueAgeSeconds }),
        };
        break;
      }
      case "pgid.queue.dlq_approximate.v1": {
        const metrics = observation.windows[window];
        if (metrics.depth !== null) {
          assertNonNegativeInteger(metrics.depth, "depth");
        }
        assertNonNegativeInteger(metrics.nonzeroMinutes, "nonzeroMinutes");
        mapped[window] = {
          nonzeroMinutes: metrics.nonzeroMinutes,
          ...(metrics.depth === null ? {} : { depth: metrics.depth }),
        };
        break;
      }
      default: {
        const exhaustive: never = observation;
        throw new Error(`unsupported alert observation: ${String(exhaustive)}`);
      }
    }
  }
  return mapped;
}

function evidenceDomain(metric: AlertMetricName): {
  kind: Exclude<AlertEvidenceMetricKind, "ratio">;
  unit: Exclude<AlertEvidenceUnit, "basis_points">;
} {
  if (
    metric === "evaluatorAgeSeconds" ||
    metric === "oldestMissingAgeSeconds" ||
    metric === "oldestUnresolvedAgeSeconds" ||
    metric === "outboxDueAgeSeconds"
  ) {
    return { kind: "age_seconds", unit: "seconds" };
  }
  if (metric === "nonzeroMinutes") {
    return { kind: "consecutive", unit: "samples" };
  }
  if (metric === "evaluatorMissing") {
    return { kind: "boolean", unit: "state" };
  }
  return { kind: "count", unit: "events" };
}

function expressionEvidence(
  expression: ThresholdExpression,
  metrics: MetricBag,
): readonly AlertMetricEvidence[] | null {
  if (expression.op === "gte") {
    const observed = metrics[expression.metric];
    if (observed === undefined || observed < expression.value) return null;
    const domain = evidenceDomain(expression.metric);
    return [{
      kind: domain.kind,
      metric: expression.metric,
      threshold: expression.value,
      unit: domain.unit,
      value: observed,
    }];
  }
  if (expression.op === "ratio_gte") {
    const numerator = metrics[expression.numerator];
    const denominator = metrics[expression.denominator];
    if (
      numerator === undefined ||
      denominator === undefined ||
      numerator < expression.minNumerator ||
      denominator < expression.minDenominator ||
      denominator === 0 ||
      BigInt(numerator) * 10_000n <
        BigInt(denominator) * BigInt(expression.basisPoints)
    ) {
      return null;
    }
    const observedBasisPoints = Number(
      (BigInt(numerator) * 10_000n) / BigInt(denominator),
    );
    return [{
      denominator,
      kind: "ratio",
      metric: "ratio",
      minNumerator: expression.minNumerator,
      minSample: expression.minDenominator,
      numerator,
      threshold: expression.basisPoints,
      unit: "basis_points",
      value: observedBasisPoints,
    }];
  }
  if (expression.op === "all") {
    const components: AlertMetricEvidence[] = [];
    for (const clause of expression.clauses) {
      const evidence = expressionEvidence(clause, metrics);
      if (evidence === null) return null;
      components.push(...evidence);
    }
    return components;
  }
  for (const clause of expression.clauses) {
    const evidence = expressionEvidence(clause, metrics);
    if (evidence !== null) return evidence;
  }
  return null;
}

function queueEvidenceKnown(observation: AlertRuleObservation): boolean {
  if (observation.ruleId !== "pgid.queue.dlq_approximate.v1") return true;
  return ALERT_WINDOW_KEYS.every(
    (window) => observation.windows[window].depth !== null,
  );
}

function isImmediateCritical(
  observation: AlertRuleObservation,
  metrics: Windowed<MetricBag>,
): boolean {
  if (observation.ruleId === "pgid.logout.delivery_health.v1") {
    return ALERT_WINDOW_KEYS.some((window) => (metrics[window].dead ?? 0) > 0);
  }
  if (observation.ruleId === "pgid.alert.runtime_health.v1") {
    return ALERT_WINDOW_KEYS.some(
      (window) =>
        (metrics[window].evaluatorMissing ?? 0) > 0 ||
        (metrics[window].evaluatorAgeSeconds ?? 0) >= 5 * 60 ||
        (metrics[window].deadOutbox ?? 0) > 0,
    );
  }
  return false;
}

export function evaluateAlertRule(
  observation: AlertRuleObservation,
): AlertRuleEvaluation {
  alertWindowsAt(observation.asOf);
  assertDimension(observation.dimension, observation.ruleId);
  const metrics = metricsForObservation(observation);
  if (!queueEvidenceKnown(observation)) {
    return {
      asOf: observation.asOf,
      breachedWindows: [],
      dimension: observation.dimension,
      evidence: "unknown",
      immediateCritical: false,
      ruleId: observation.ruleId,
      selectedEvidence: null,
      severity: "none",
    };
  }

  const definition = ALERT_RULE_DEFINITIONS[observation.ruleId];
  const criticalMatches = ALERT_EVIDENCE_WINDOW_ORDER.flatMap((window) => {
    const threshold = definition.thresholds[window].critical;
    if (threshold === null) return [];
    const components = expressionEvidence(threshold, metrics[window]);
    return components === null ? [] : [{ components, window }];
  });
  if (criticalMatches.length > 0) {
    const selected = criticalMatches[0];
    const primary = selected.components[0];
    return {
      asOf: observation.asOf,
      breachedWindows: criticalMatches.map(({ window }) => window),
      dimension: observation.dimension,
      evidence: "known",
      immediateCritical: isImmediateCritical(observation, metrics),
      ruleId: observation.ruleId,
      selectedEvidence: {
        ...primary,
        components: selected.components,
        provenance: definition.provenance,
        severity: "critical",
        window: selected.window,
      },
      severity: "critical",
    };
  }

  const warningMatches = ALERT_EVIDENCE_WINDOW_ORDER.flatMap((window) => {
    const threshold = definition.thresholds[window].warning;
    if (threshold === null) return [];
    const components = expressionEvidence(threshold, metrics[window]);
    return components === null ? [] : [{ components, window }];
  });
  const selected = warningMatches[0];
  const primary = selected?.components[0];
  return {
    asOf: observation.asOf,
    breachedWindows: warningMatches.map(({ window }) => window),
    dimension: observation.dimension,
    evidence: "known",
    immediateCritical: false,
    ruleId: observation.ruleId,
    selectedEvidence: selected && primary
      ? {
          ...primary,
          components: selected.components,
          provenance: definition.provenance,
          severity: "warning",
          window: selected.window,
        }
      : null,
    severity: warningMatches.length > 0 ? "warning" : "none",
  };
}

export function definitionForAlertRule(
  ruleId: AlertRuleId,
): AlertRuleDefinition {
  return ALERT_RULE_DEFINITIONS[ruleId];
}
