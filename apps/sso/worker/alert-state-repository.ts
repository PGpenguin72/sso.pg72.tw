import {
  ALERT_RULE_DEFINITIONS,
  parseAlertDimension,
  parseAlertRuleId,
  parseAlertSelectedEvidenceForRule,
  type AlertDimension,
  type AlertRuleEvaluation,
  type AlertRuleId,
  type AlertSelectedEvidence,
  type AlertSeverity,
  type AlertSourceKind,
} from "./alert-rules";
import type {
  AlertActionIntent,
  AlertLifecycleIdentity,
  AlertLifecycleResult,
  AlertLifecycleState,
} from "./alert-evaluator";

const MAX_STATE_GENERATION = 1_000_000;
const MAX_STATE_REVISION = 1_000_000_000;
const MAX_EVENT_SEQUENCE = 1_000_000_000;
const EMAIL_CHANNEL = "email";

export type AlertEnvironment = "local" | "preview" | "production";
export type AlertStatePersistenceResult = "applied" | "conflict" | "duplicate";

export interface AlertExpectedIncident {
  id: string;
  status: "acknowledged" | "open";
}

export interface AlertStateCasExpectation {
  generation: number;
  incident: AlertExpectedIncident | null;
  lastEvaluatedAt: string;
  revision: number;
  stateId: string;
}

export interface PersistAlertLifecycleDecisionInput {
  decision: AlertLifecycleResult;
  environment: AlertEnvironment;
  evaluation: AlertRuleEvaluation;
  expected: AlertStateCasExpectation | null;
}

export type AlertStateRepositoryErrorCode =
  | "invalid_input"
  | "source_invalid"
  | "source_unavailable"
  | "write_failed";

export class AlertStateRepositoryError extends Error {
  readonly code: AlertStateRepositoryErrorCode;

  constructor(code: AlertStateRepositoryErrorCode) {
    super(`Alert state repository failed (${code})`);
    this.name = "AlertStateRepositoryError";
    this.code = code;
  }
}

type ActiveSeverity = Exclude<AlertSeverity, "none">;
type IncidentStatus = "acknowledged" | "open" | "resolved";
type UnknownRecord = Record<string, unknown>;

interface CanonicalTimestamp {
  iso: string;
  time: number;
}

interface DimensionColumns {
  hashVersion: 1 | null;
  queueName: string | null;
  subjectRef: string | null;
}

interface EvidenceColumns {
  criticalThreshold: number | null;
  metricKind: AlertSelectedEvidence["kind"];
  metricName: AlertSelectedEvidence["metricName"];
  metricUnit: AlertSelectedEvidence["unit"];
  minimumNumeratorCount: number | null;
  minimumSampleCount: number;
  observedDenominator: number | null;
  observedNumerator: number | null;
  observedValue: number;
  secondaryMetricKind: AlertSelectedEvidence["kind"] | null;
  secondaryMetricName: AlertSelectedEvidence["metricName"] | null;
  secondaryMetricUnit: AlertSelectedEvidence["unit"] | null;
  secondaryObservedValue: number | null;
  secondaryThreshold: number | null;
  severity: ActiveSeverity;
  threshold: number;
  warningThreshold: number | null;
  windowSeconds: 300 | 900 | 3_600;
}

interface IncidentProjection {
  acknowledgedAt: string | null;
  acknowledgedByHashVersion: number | null;
  acknowledgedByRef: string | null;
  createdAt: string;
  environment: AlertEnvironment;
  firstSeenAt: string;
  generation: number;
  id: string;
  lastSeenAt: string;
  metricKind: AlertSelectedEvidence["kind"];
  metricName: AlertSelectedEvidence["metricName"];
  metricUnit: AlertSelectedEvidence["unit"];
  minimumNumeratorCount: number | null;
  minimumSampleCount: number;
  observedDenominator: number | null;
  observedNumerator: number | null;
  observedValue: number;
  ruleId: AlertRuleId;
  secondaryMetricKind: AlertSelectedEvidence["kind"] | null;
  secondaryMetricName: AlertSelectedEvidence["metricName"] | null;
  secondaryMetricUnit: AlertSelectedEvidence["unit"] | null;
  secondaryObservedValue: number | null;
  secondaryThreshold: number | null;
  severity: ActiveSeverity;
  sourceKind: AlertSourceKind;
  stateId: string;
  status: IncidentStatus;
  threshold: number;
  updatedAt: string;
  windowSeconds: 300 | 900 | 3_600;
}

interface StateProjection {
  breachSeverity: ActiveSeverity | null;
  consecutiveBreaches: number;
  consecutiveClears: number;
  cooldownUntil: string | null;
  criticalThreshold: number | null;
  currentSeverity: AlertSeverity;
  dedupeKey: string;
  environment: AlertEnvironment;
  generation: number;
  hashVersion: number | null;
  id: string;
  lastEvaluatedAt: string;
  lastNotificationScheduledAt: string | null;
  metricKind: AlertSelectedEvidence["kind"];
  metricName: AlertSelectedEvidence["metricName"];
  metricUnit: AlertSelectedEvidence["unit"];
  minimumNumeratorCount: number | null;
  minimumSampleCount: number;
  observedDenominator: number | null;
  observedNumerator: number | null;
  observedValue: number;
  queueName: string | null;
  revision: number;
  ruleId: AlertRuleId;
  secondaryMetricKind: AlertSelectedEvidence["kind"] | null;
  secondaryMetricName: AlertSelectedEvidence["metricName"] | null;
  secondaryMetricUnit: AlertSelectedEvidence["unit"] | null;
  secondaryObservedValue: number | null;
  secondaryThreshold: number | null;
  sourceKind: AlertSourceKind;
  subjectRef: string | null;
  warningThreshold: number | null;
  windowSeconds: 300 | 900 | 3_600;
}

interface DeliverySnapshot {
  channel: "email";
  createdAt: string;
  deliveryKey: string;
  eventKind: "escalated" | "opened" | "reminder" | "resolved";
  eventSequence: number;
  idempotencyKey: string;
  payloadJson: string;
  payloadSha256: string;
}

interface PlannedEvent {
  eventKind: DeliverySnapshot["eventKind"];
  eventSequence: number;
  incident: IncidentProjection;
  incidentStatus: IncidentStatus;
  severity: ActiveSeverity;
}

function fail(code: AlertStateRepositoryErrorCode): never {
  throw new AlertStateRepositoryError(code);
}

function isRepositoryErrorCode(
  value: unknown,
): value is AlertStateRepositoryErrorCode {
  return value === "invalid_input" ||
    value === "source_invalid" ||
    value === "source_unavailable" ||
    value === "write_failed";
}

function exactLocalRepositoryErrorCode(
  error: unknown,
): AlertStateRepositoryErrorCode | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  try {
    if (Object.getPrototypeOf(error) !== AlertStateRepositoryError.prototype) {
      return undefined;
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, "code");
    return descriptor && "value" in descriptor &&
        isRepositoryErrorCode(descriptor.value)
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function redactedRepositoryError(
  error: unknown,
  fallback: AlertStateRepositoryErrorCode,
): AlertStateRepositoryError {
  return new AlertStateRepositoryError(
    exactLocalRepositoryErrorCode(error) ?? fallback,
  );
}

function recordValue(value: unknown): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("invalid_input");
  }
  return value as UnknownRecord;
}

function exactRecord(value: unknown, keys: readonly string[]): UnknownRecord {
  const record = recordValue(value);
  const actual = Object.keys(record);
  if (
    actual.length !== keys.length ||
    keys.some((key) => !Object.hasOwn(record, key))
  ) {
    fail("invalid_input");
  }
  return record;
}

function canonicalTimestamp(value: unknown): CanonicalTimestamp {
  if (typeof value !== "string") fail("invalid_input");
  const time = new Date(value).getTime();
  if (
    value.length !== 24 ||
    !Number.isFinite(time) ||
    new Date(time).toISOString() !== value
  ) {
    fail("invalid_input");
  }
  return { iso: value, time };
}

function nullableTimestamp(value: unknown): string | null {
  return value === null ? null : canonicalTimestamp(value).iso;
}

function boundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    fail("invalid_input");
  }
  return value;
}

function uuidV4(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      value,
    )
  ) {
    fail("invalid_input");
  }
  return value;
}

function environment(value: unknown): AlertEnvironment {
  if (value === "local" || value === "preview" || value === "production") {
    return value;
  }
  fail("invalid_input");
}

function sourceKindFor(ruleId: AlertRuleId): AlertSourceKind {
  return ALERT_RULE_DEFINITIONS[ruleId].sourceKind;
}

function sameDimension(left: AlertDimension, right: AlertDimension): boolean {
  if (left.kind !== right.kind) return false;
  if (left.kind === "global" && right.kind === "global") return true;
  if (left.kind === "queue" && right.kind === "queue") {
    return left.queue === right.queue;
  }
  return "reference" in left && "reference" in right &&
    left.reference.keyVersion === right.reference.keyVersion &&
    left.reference.value === right.reference.value;
}

function dimensionColumns(dimension: AlertDimension): DimensionColumns {
  if (dimension.kind === "global") {
    return { hashVersion: null, queueName: null, subjectRef: null };
  }
  if (dimension.kind === "queue") {
    return { hashVersion: null, queueName: dimension.queue, subjectRef: null };
  }
  return {
    hashVersion: dimension.reference.keyVersion,
    queueName: null,
    subjectRef: dimension.reference.value,
  };
}

function normalizeEvaluation(value: unknown): AlertRuleEvaluation {
  const record = exactRecord(value, [
    "asOf",
    "breachedWindows",
    "dimension",
    "evidence",
    "immediateCritical",
    "ruleId",
    "selectedEvidence",
    "severity",
  ]);
  const ruleId = parseAlertRuleId(record.ruleId);
  const asOf = canonicalTimestamp(record.asOf).iso;
  const dimension = parseAlertDimension(
    record.dimension,
    ALERT_RULE_DEFINITIONS[ruleId].dimensions,
  );
  if (!Array.isArray(record.breachedWindows)) fail("invalid_input");
  const breachedWindows = record.breachedWindows.map((window) => {
    if (window !== "5m" && window !== "15m" && window !== "60m") {
      fail("invalid_input");
    }
    return window;
  });
  if (new Set(breachedWindows).size !== breachedWindows.length) {
    fail("invalid_input");
  }
  const evidence = record.evidence;
  if (evidence !== "known" && evidence !== "unknown") fail("invalid_input");
  const severity = record.severity;
  if (severity !== "none" && severity !== "warning" && severity !== "critical") {
    fail("invalid_input");
  }
  const selectedEvidence = record.selectedEvidence === null
    ? null
    : parseAlertSelectedEvidenceForRule(record.selectedEvidence, ruleId);
  const immediateCritical = selectedEvidence !== null && (
    ruleId === "pgid.logout.delivery_health.v1"
      ? selectedEvidence.metricName === "dead"
      : ruleId === "pgid.alert.runtime_health.v1" &&
        (selectedEvidence.metricName === "evaluator_missing" ||
          selectedEvidence.metricName === "dead_outbox")
  );
  if (
    typeof record.immediateCritical !== "boolean" ||
    (severity === "none") !== (selectedEvidence === null) ||
    (selectedEvidence !== null && selectedEvidence.severity !== severity) ||
    (evidence === "unknown" &&
      (severity !== "none" || selectedEvidence !== null || breachedWindows.length !== 0)) ||
    record.immediateCritical !== immediateCritical ||
    (immediateCritical && severity !== "critical")
  ) {
    fail("invalid_input");
  }
  return {
    asOf,
    breachedWindows,
    dimension,
    evidence,
    immediateCritical,
    ruleId,
    selectedEvidence,
    severity,
  };
}

function normalizeIdentity(
  value: unknown,
  ruleId: AlertRuleId,
): AlertLifecycleIdentity {
  const record = exactRecord(value, ["dimension", "ruleId"]);
  const parsedRuleId = parseAlertRuleId(record.ruleId);
  if (parsedRuleId !== ruleId) fail("invalid_input");
  return {
    dimension: parseAlertDimension(
      record.dimension,
      ALERT_RULE_DEFINITIONS[ruleId].dimensions,
    ),
    ruleId,
  };
}

function normalizeLifecycleState(
  value: unknown,
  evaluation: AlertRuleEvaluation,
): AlertLifecycleState {
  const record = exactRecord(value, [
    "activeEvidence",
    "breachEvidence",
    "breachSeverity",
    "consecutiveBreaches",
    "consecutiveClears",
    "cooldownUntil",
    "identity",
    "lastEvaluatedAt",
    "lastNotificationAt",
    "openedAt",
    "phase",
    "status",
  ]);
  const identity = record.identity === null
    ? null
    : normalizeIdentity(record.identity, evaluation.ruleId);
  if (
    identity !== null &&
    !sameDimension(identity.dimension, evaluation.dimension)
  ) {
    fail("invalid_input");
  }
  const parseEvidence = (entry: unknown): AlertSelectedEvidence | null =>
    entry === null
      ? null
      : parseAlertSelectedEvidenceForRule(entry, evaluation.ruleId);
  const activeEvidence = parseEvidence(record.activeEvidence);
  const breachEvidence = parseEvidence(record.breachEvidence);
  const breachSeverity = record.breachSeverity;
  if (
    breachSeverity !== null &&
    breachSeverity !== "warning" &&
    breachSeverity !== "critical"
  ) {
    fail("invalid_input");
  }
  const phase = record.phase;
  if (phase !== "active" && phase !== "inactive" && phase !== "pending") {
    fail("invalid_input");
  }
  const status = record.status;
  if (status !== "none" && status !== "warning" && status !== "critical") {
    fail("invalid_input");
  }
  const state: AlertLifecycleState = {
    activeEvidence,
    breachEvidence,
    breachSeverity,
    consecutiveBreaches: boundedInteger(record.consecutiveBreaches, 0, 1),
    consecutiveClears: boundedInteger(record.consecutiveClears, 0, 4),
    cooldownUntil: nullableTimestamp(record.cooldownUntil),
    identity,
    lastEvaluatedAt: nullableTimestamp(record.lastEvaluatedAt),
    lastNotificationAt: nullableTimestamp(record.lastNotificationAt),
    openedAt: nullableTimestamp(record.openedAt),
    phase,
    status,
  };
  if (
    (state.identity === null) !== (state.lastEvaluatedAt === null) ||
    (state.breachSeverity === null) !== (state.breachEvidence === null) ||
    (state.breachSeverity === null) !== (state.consecutiveBreaches === 0) ||
    (state.breachEvidence !== null &&
      state.breachEvidence.severity !== state.breachSeverity) ||
    (state.activeEvidence !== null &&
      state.activeEvidence.severity !== state.status) ||
    (state.lastEvaluatedAt !== null &&
      state.lastEvaluatedAt !== evaluation.asOf)
  ) {
    fail("invalid_input");
  }
  if (state.phase === "inactive") {
    if (
      state.status !== "none" || state.activeEvidence !== null ||
      state.breachEvidence !== null || state.openedAt !== null ||
      state.lastNotificationAt !== null || state.consecutiveClears !== 0
    ) {
      fail("invalid_input");
    }
  } else if (state.phase === "pending") {
    if (
      state.status !== "none" || state.activeEvidence !== null ||
      state.breachEvidence === null || state.identity === null ||
      state.openedAt !== null || state.lastNotificationAt !== null ||
      state.consecutiveClears !== 0
    ) {
      fail("invalid_input");
    }
  } else if (
    state.status === "none" || state.activeEvidence === null ||
    state.identity === null || state.openedAt === null ||
    state.lastNotificationAt === null || state.cooldownUntil !== null
  ) {
    fail("invalid_input");
  }
  return state;
}

function normalizeIntent(
  value: unknown,
  evaluation: AlertRuleEvaluation,
): AlertActionIntent | null {
  if (value === null) return null;
  const base = recordValue(value);
  const kind = base.kind;
  const keys = kind === "open"
    ? ["at", "dimension", "evidence", "kind", "mode", "ruleId", "severity"]
    : kind === "escalate"
      ? ["at", "dimension", "evidence", "from", "kind", "mode", "ruleId", "severity"]
      : kind === "remind"
        ? ["at", "dimension", "evidence", "kind", "mode", "ruleId", "severity"]
        : kind === "resolve"
          ? ["at", "dimension", "from", "kind", "mode", "ruleId", "severity"]
          : fail("invalid_input");
  const record = exactRecord(value, keys);
  if (
    record.at !== evaluation.asOf || record.mode !== "observe_only" ||
    record.ruleId !== evaluation.ruleId
  ) {
    fail("invalid_input");
  }
  const dimension = parseAlertDimension(
    record.dimension,
    ALERT_RULE_DEFINITIONS[evaluation.ruleId].dimensions,
  );
  if (!sameDimension(dimension, evaluation.dimension)) fail("invalid_input");
  if (kind === "resolve") {
    if (
      (record.from !== "warning" && record.from !== "critical") ||
      record.severity !== "none"
    ) {
      fail("invalid_input");
    }
    return {
      at: evaluation.asOf,
      dimension,
      from: record.from,
      kind,
      mode: "observe_only",
      ruleId: evaluation.ruleId,
      severity: "none",
    };
  }
  const evidence = parseAlertSelectedEvidenceForRule(
    record.evidence,
    evaluation.ruleId,
  );
  if (record.severity !== evidence.severity) fail("invalid_input");
  if (kind === "escalate") {
    if (record.from !== "warning" || record.severity !== "critical") {
      fail("invalid_input");
    }
    return {
      at: evaluation.asOf,
      dimension,
      evidence,
      from: "warning",
      kind,
      mode: "observe_only",
      ruleId: evaluation.ruleId,
      severity: "critical",
    };
  }
  if (record.severity !== "warning" && record.severity !== "critical") {
    fail("invalid_input");
  }
  return {
    at: evaluation.asOf,
    dimension,
    evidence,
    kind: kind === "open" ? "open" : "remind",
    mode: "observe_only",
    ruleId: evaluation.ruleId,
    severity: record.severity,
  };
}

function normalizeDecision(
  value: unknown,
  evaluation: AlertRuleEvaluation,
): AlertLifecycleResult {
  const record = exactRecord(value, ["intent", "state"]);
  const state = normalizeLifecycleState(record.state, evaluation);
  const intent = normalizeIntent(record.intent, evaluation);
  if (
    (state.identity === null && intent !== null) ||
    (intent?.kind === "open" && state.status === "none") ||
    (intent?.kind === "escalate" && state.status !== "critical") ||
    (intent?.kind === "remind" && state.status !== intent.severity) ||
    (intent?.kind === "resolve" && state.status !== "none")
  ) {
    fail("invalid_input");
  }
  return { intent, state };
}

function normalizeExpectation(value: unknown): AlertStateCasExpectation | null {
  if (value === null) return null;
  const record = exactRecord(value, [
    "generation",
    "incident",
    "lastEvaluatedAt",
    "revision",
    "stateId",
  ]);
  let incident: AlertExpectedIncident | null = null;
  if (record.incident !== null) {
    const expectedIncident = exactRecord(record.incident, ["id", "status"]);
    if (
      expectedIncident.status !== "open" &&
      expectedIncident.status !== "acknowledged"
    ) {
      fail("invalid_input");
    }
    incident = {
      id: uuidV4(expectedIncident.id),
      status: expectedIncident.status,
    };
  }
  return {
    generation: boundedInteger(record.generation, 0, MAX_STATE_GENERATION),
    incident,
    lastEvaluatedAt: canonicalTimestamp(record.lastEvaluatedAt).iso,
    revision: boundedInteger(record.revision, 0, MAX_STATE_REVISION),
    stateId: uuidV4(record.stateId),
  };
}

function evidenceColumns(evidence: AlertSelectedEvidence): EvidenceColumns {
  const secondary = evidence.secondary;
  return {
    criticalThreshold: evidence.severity === "critical" ? evidence.threshold : null,
    metricKind: evidence.kind,
    metricName: evidence.metricName,
    metricUnit: evidence.unit,
    minimumNumeratorCount: evidence.minimumNumeratorCount,
    minimumSampleCount: evidence.minimumSampleCount,
    observedDenominator: evidence.observedDenominator,
    observedNumerator: evidence.observedNumerator,
    observedValue: evidence.observedValue,
    secondaryMetricKind: secondary?.kind ?? null,
    secondaryMetricName: secondary?.metricName ?? null,
    secondaryMetricUnit: secondary?.unit ?? null,
    secondaryObservedValue: secondary?.observedValue ?? null,
    secondaryThreshold: secondary?.threshold ?? null,
    severity: evidence.severity,
    threshold: evidence.threshold,
    warningThreshold: evidence.severity === "warning" ? evidence.threshold : null,
    windowSeconds: evidence.windowSeconds,
  };
}

function persistedEvidence(
  state: AlertLifecycleState,
  evaluation: AlertRuleEvaluation,
): EvidenceColumns | null {
  if (evaluation.evidence !== "known" || evaluation.severity === "none") {
    return null;
  }
  const evidence = state.breachEvidence ?? state.activeEvidence;
  if (evidence === null) fail("invalid_input");
  return evidenceColumns(evidence);
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

async function digestBytes(value: string): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
  );
}

async function canonicalReference(
  domain: string,
  fields: readonly (number | string)[],
): Promise<string> {
  return bytesToBase64url(
    await digestBytes(JSON.stringify([domain, ...fields])),
  );
}

async function sha256Hex(value: string): Promise<string> {
  return [...await digestBytes(value)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function incidentFromEvidence(
  options: {
    environment: AlertEnvironment;
    evidence: EvidenceColumns;
    firstSeenAt: string;
    generation: number;
    id: string;
    lastSeenAt: string;
    ruleId: AlertRuleId;
    severity: ActiveSeverity;
    sourceKind: AlertSourceKind;
    stateId: string;
  },
): IncidentProjection {
  const evidence = options.evidence;
  return {
    acknowledgedAt: null,
    acknowledgedByHashVersion: null,
    acknowledgedByRef: null,
    createdAt: options.firstSeenAt,
    environment: options.environment,
    firstSeenAt: options.firstSeenAt,
    generation: options.generation,
    id: options.id,
    lastSeenAt: options.lastSeenAt,
    metricKind: evidence.metricKind,
    metricName: evidence.metricName,
    metricUnit: evidence.metricUnit,
    minimumNumeratorCount: evidence.minimumNumeratorCount,
    minimumSampleCount: evidence.minimumSampleCount,
    observedDenominator: evidence.observedDenominator,
    observedNumerator: evidence.observedNumerator,
    observedValue: evidence.observedValue,
    ruleId: options.ruleId,
    secondaryMetricKind: evidence.secondaryMetricKind,
    secondaryMetricName: evidence.secondaryMetricName,
    secondaryMetricUnit: evidence.secondaryMetricUnit,
    secondaryObservedValue: evidence.secondaryObservedValue,
    secondaryThreshold: evidence.secondaryThreshold,
    severity: options.severity,
    sourceKind: options.sourceKind,
    stateId: options.stateId,
    status: "open",
    threshold: evidence.threshold,
    updatedAt: options.firstSeenAt,
    windowSeconds: evidence.windowSeconds,
  };
}

function parseIncidentProjection(value: unknown): IncidentProjection {
  const record = exactRecord(value, [
    "acknowledged_at",
    "acknowledged_by_hash_version",
    "acknowledged_by_ref",
    "created_at",
    "environment",
    "first_seen_at",
    "generation",
    "id",
    "last_seen_at",
    "metric_kind",
    "metric_name",
    "metric_unit",
    "minimum_numerator_count",
    "minimum_sample_count",
    "observed_denominator",
    "observed_numerator",
    "observed_value",
    "rule_id",
    "secondary_metric_kind",
    "secondary_metric_name",
    "secondary_metric_unit",
    "secondary_observed_value",
    "secondary_threshold",
    "severity",
    "source_kind",
    "state_id",
    "status",
    "threshold",
    "updated_at",
    "window_seconds",
  ]);
  const severity = record.severity;
  const status = record.status;
  const sourceKind = record.source_kind;
  if (
    (severity !== "warning" && severity !== "critical") ||
    (status !== "open" && status !== "acknowledged" && status !== "resolved") ||
    (sourceKind !== "d1_exact" && sourceKind !== "queue_approximate")
  ) {
    fail("source_invalid");
  }
  const metric = {
    kind: record.metric_kind,
    metricName: record.metric_name,
    minimumNumeratorCount: record.minimum_numerator_count,
    minimumSampleCount: record.minimum_sample_count,
    observedDenominator: record.observed_denominator,
    observedNumerator: record.observed_numerator,
    observedValue: record.observed_value,
    secondary: record.secondary_metric_name === null
      ? null
      : {
          kind: record.secondary_metric_kind,
          metricName: record.secondary_metric_name,
          minimumNumeratorCount: null,
          minimumSampleCount: 0,
          observedDenominator: null,
          observedNumerator: null,
          observedValue: record.secondary_observed_value,
          threshold: record.secondary_threshold,
          unit: record.secondary_metric_unit,
        },
    severity,
    threshold: record.threshold,
    unit: record.metric_unit,
    windowSeconds: record.window_seconds,
  };
  const ruleId = parseAlertRuleId(record.rule_id);
  let evidence: AlertSelectedEvidence;
  try {
    evidence = parseAlertSelectedEvidenceForRule(metric, ruleId);
  } catch {
    fail("source_invalid");
  }
  return {
    acknowledgedAt: nullableTimestamp(record.acknowledged_at),
    acknowledgedByHashVersion: record.acknowledged_by_hash_version === null
      ? null
      : boundedInteger(record.acknowledged_by_hash_version, 1, 1),
    acknowledgedByRef: record.acknowledged_by_ref === null
      ? null
      : String(record.acknowledged_by_ref),
    createdAt: canonicalTimestamp(record.created_at).iso,
    environment: environment(record.environment),
    firstSeenAt: canonicalTimestamp(record.first_seen_at).iso,
    generation: boundedInteger(record.generation, 1, MAX_STATE_GENERATION),
    id: uuidV4(record.id),
    lastSeenAt: canonicalTimestamp(record.last_seen_at).iso,
    metricKind: evidence.kind,
    metricName: evidence.metricName,
    metricUnit: evidence.unit,
    minimumNumeratorCount: evidence.minimumNumeratorCount,
    minimumSampleCount: evidence.minimumSampleCount,
    observedDenominator: evidence.observedDenominator,
    observedNumerator: evidence.observedNumerator,
    observedValue: evidence.observedValue,
    ruleId,
    secondaryMetricKind: evidence.secondary?.kind ?? null,
    secondaryMetricName: evidence.secondary?.metricName ?? null,
    secondaryMetricUnit: evidence.secondary?.unit ?? null,
    secondaryObservedValue: evidence.secondary?.observedValue ?? null,
    secondaryThreshold: evidence.secondary?.threshold ?? null,
    severity,
    sourceKind,
    stateId: uuidV4(record.state_id),
    status,
    threshold: evidence.threshold,
    updatedAt: canonicalTimestamp(record.updated_at).iso,
    windowSeconds: evidence.windowSeconds,
  };
}

const INCIDENT_PROJECTION = `
  id, state_id, rule_id, environment, generation, severity, status,
  source_kind, first_seen_at, last_seen_at, window_seconds,
  metric_name, metric_kind, metric_unit, observed_value,
  observed_numerator, observed_denominator, minimum_sample_count,
  minimum_numerator_count, threshold, secondary_metric_name,
  secondary_metric_kind, secondary_metric_unit, secondary_observed_value,
  secondary_threshold, acknowledged_at, acknowledged_by_ref,
  acknowledged_by_hash_version, created_at, updated_at`;

async function readExpectedIncident(
  database: D1Database,
  expected: AlertStateCasExpectation,
  ruleId: AlertRuleId,
  environmentValue: AlertEnvironment,
  sourceKind: AlertSourceKind,
): Promise<IncidentProjection | null> {
  if (expected.incident === null) return null;
  let row: unknown;
  try {
    row = await database.prepare(
      `SELECT ${INCIDENT_PROJECTION}
         FROM security_alert
        WHERE id = ? AND state_id = ? AND rule_id = ? AND environment = ?
          AND generation = ? AND source_kind = ?`,
    ).bind(
      expected.incident.id,
      expected.stateId,
      ruleId,
      environmentValue,
      expected.generation,
      sourceKind,
    ).first();
  } catch (error) {
    throw redactedRepositoryError(error, "source_unavailable");
  }
  if (row === null) return null;
  try {
    return parseIncidentProjection(row);
  } catch (error) {
    throw redactedRepositoryError(error, "source_invalid");
  }
}

async function nextReminderSequence(
  database: D1Database,
  incident: IncidentProjection,
): Promise<number> {
  let value: unknown;
  try {
    value = await database.prepare(
      `SELECT coalesce(max(event_sequence) + 1, 1) AS next_sequence
         FROM alert_outbox
        WHERE alert_id = ? AND generation = ?
          AND event_kind = 'reminder' AND channel = 'email'`,
    ).bind(incident.id, incident.generation).first("next_sequence");
  } catch (error) {
    throw redactedRepositoryError(error, "source_unavailable");
  }
  try {
    return boundedInteger(value, 1, MAX_EVENT_SEQUENCE);
  } catch (error) {
    throw redactedRepositoryError(error, "source_invalid");
  }
}

function incidentWithEvidence(
  current: IncidentProjection,
  evidence: EvidenceColumns,
  severity: ActiveSeverity,
  at: string,
): IncidentProjection {
  return {
    ...current,
    lastSeenAt: at,
    metricKind: evidence.metricKind,
    metricName: evidence.metricName,
    metricUnit: evidence.metricUnit,
    minimumNumeratorCount: evidence.minimumNumeratorCount,
    minimumSampleCount: evidence.minimumSampleCount,
    observedDenominator: evidence.observedDenominator,
    observedNumerator: evidence.observedNumerator,
    observedValue: evidence.observedValue,
    secondaryMetricKind: evidence.secondaryMetricKind,
    secondaryMetricName: evidence.secondaryMetricName,
    secondaryMetricUnit: evidence.secondaryMetricUnit,
    secondaryObservedValue: evidence.secondaryObservedValue,
    secondaryThreshold: evidence.secondaryThreshold,
    severity,
    threshold: evidence.threshold,
    updatedAt: at,
    windowSeconds: evidence.windowSeconds,
  };
}

function canonicalPayload(
  event: PlannedEvent,
  deliveryKey: string,
  idempotencyKey: string,
  dimensions: DimensionColumns,
): string {
  const incident = event.incident;
  return JSON.stringify({
    schemaVersion: 1,
    templateVersion: 1,
    incidentId: incident.id,
    generation: incident.generation,
    deliveryId: deliveryKey,
    idempotencyKey,
    eventKind: event.eventKind,
    eventSequence: event.eventSequence,
    channel: EMAIL_CHANNEL,
    rule: incident.ruleId,
    environment: incident.environment,
    sourceKind: incident.sourceKind,
    severity: event.severity,
    status: event.incidentStatus,
    firstSeenAt: incident.firstSeenAt,
    lastSeenAt: incident.lastSeenAt,
    windowSeconds: incident.windowSeconds,
    metricName: incident.metricName,
    metricKind: incident.metricKind,
    metricUnit: incident.metricUnit,
    observedValue: incident.observedValue,
    observedNumerator: incident.observedNumerator,
    observedDenominator: incident.observedDenominator,
    minimumSampleCount: incident.minimumSampleCount,
    minimumNumeratorCount: incident.minimumNumeratorCount,
    threshold: incident.threshold,
    secondaryMetricName: incident.secondaryMetricName,
    secondaryMetricKind: incident.secondaryMetricKind,
    secondaryMetricUnit: incident.secondaryMetricUnit,
    secondaryObservedValue: incident.secondaryObservedValue,
    secondaryThreshold: incident.secondaryThreshold,
    subjectRef: dimensions.subjectRef,
    hashVersion: dimensions.hashVersion,
    provider: null,
    queue: dimensions.queueName,
    reason: null,
    surface: null,
  });
}

async function deliverySnapshot(
  event: PlannedEvent,
  dimensions: DimensionColumns,
  at: string,
): Promise<DeliverySnapshot> {
  const identityFields = [
    event.incident.id,
    event.incident.generation,
    event.eventKind,
    event.eventSequence,
    EMAIL_CHANNEL,
  ] as const;
  const deliveryKey = `pgid_ad_${await canonicalReference(
    "pgid.alert.delivery.v1",
    identityFields,
  )}`;
  const idempotencyKey = await canonicalReference(
    "pgid.alert.idempotency.v1",
    identityFields,
  );
  const payloadJson = canonicalPayload(
    event,
    deliveryKey,
    idempotencyKey,
    dimensions,
  );
  return {
    channel: EMAIL_CHANNEL,
    createdAt: at,
    deliveryKey,
    eventKind: event.eventKind,
    eventSequence: event.eventSequence,
    idempotencyKey,
    payloadJson,
    payloadSha256: await sha256Hex(payloadJson),
  };
}

function prepareStateInsert(
  database: D1Database,
  options: {
    at: string;
    dedupeKey: string;
    dimensions: DimensionColumns;
    environment: AlertEnvironment;
    evidence: EvidenceColumns;
    ruleId: AlertRuleId;
    sourceKind: AlertSourceKind;
    stateId: string;
  },
): D1PreparedStatement {
  const evidence = options.evidence;
  return database.prepare(
    `INSERT INTO alert_state
      (id, rule_id, environment, source_kind, dedupe_key,
       subject_ref, hash_version, provider, queue_name, reason, surface,
       window_seconds, metric_name, metric_kind, metric_unit, observed_value,
       observed_numerator, observed_denominator, minimum_sample_count,
       minimum_numerator_count, warning_threshold, critical_threshold,
       secondary_metric_name, secondary_metric_kind, secondary_metric_unit,
       secondary_observed_value, secondary_threshold,
       consecutive_breaches, breach_severity, consecutive_clears,
       current_severity, generation, revision, cooldown_until,
       last_evaluated_at, last_breached_at, last_cleared_at,
       last_notification_scheduled_at, created_at, updated_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL, NULL,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            1, ?, 0, 'none', 0, 0, NULL, ?, ?, NULL, NULL, ?, ?
      WHERE NOT EXISTS (
        SELECT 1 FROM alert_state
         WHERE rule_id = ? AND environment = ? AND source_kind = ?
           AND subject_ref IS ? AND queue_name IS ?
      )`,
  ).bind(
    options.stateId,
    options.ruleId,
    options.environment,
    options.sourceKind,
    options.dedupeKey,
    options.dimensions.subjectRef,
    options.dimensions.hashVersion,
    options.dimensions.queueName,
    evidence.windowSeconds,
    evidence.metricName,
    evidence.metricKind,
    evidence.metricUnit,
    evidence.observedValue,
    evidence.observedNumerator,
    evidence.observedDenominator,
    evidence.minimumSampleCount,
    evidence.minimumNumeratorCount,
    evidence.warningThreshold,
    evidence.criticalThreshold,
    evidence.secondaryMetricName,
    evidence.secondaryMetricKind,
    evidence.secondaryMetricUnit,
    evidence.secondaryObservedValue,
    evidence.secondaryThreshold,
    evidence.severity,
    options.at,
    options.at,
    options.at,
    options.at,
    options.ruleId,
    options.environment,
    options.sourceKind,
    options.dimensions.subjectRef,
    options.dimensions.queueName,
  );
}

function expectedIncidentPredicate(expected: AlertStateCasExpectation): string {
  return expected.incident === null
    ? `NOT EXISTS (
         SELECT 1 FROM security_alert AS expected_incident
          WHERE expected_incident.state_id = alert_state.id
            AND expected_incident.status IN ('open', 'acknowledged')
       )`
    : `EXISTS (
         SELECT 1 FROM security_alert AS expected_incident
          WHERE expected_incident.id = ?
            AND expected_incident.state_id = alert_state.id
            AND expected_incident.generation = ?
            AND expected_incident.status = ?
            AND expected_incident.updated_at = ?
       )`;
}

function prepareStateUpdate(
  database: D1Database,
  options: {
    at: string;
    decision: AlertLifecycleResult;
    dedupeKey: string;
    dimensions: DimensionColumns;
    environment: AlertEnvironment;
    evaluation: AlertRuleEvaluation;
    expected: AlertStateCasExpectation;
    expectedIncident: IncidentProjection | null;
    evidence: EvidenceColumns | null;
    generation: number;
    ruleId: AlertRuleId;
    sourceKind: AlertSourceKind;
  },
): D1PreparedStatement {
  const state = options.decision.state;
  const replaceEvidence = options.evidence === null ? 0 : 1;
  const evidence = options.evidence;
  const knownBreach = options.evaluation.evidence === "known" &&
      options.evaluation.severity !== "none"
    ? 1
    : 0;
  const knownClear = options.evaluation.evidence === "known" &&
      options.evaluation.severity === "none"
    ? 1
    : 0;
  const unknownGuard = options.evaluation.evidence === "unknown"
    ? "AND current_severity = ? AND generation = ?"
    : "";
  const incidentPredicate = expectedIncidentPredicate(options.expected);
  const statement = database.prepare(
    `UPDATE alert_state
        SET window_seconds = CASE WHEN ? = 1 THEN ? ELSE window_seconds END,
            metric_name = CASE WHEN ? = 1 THEN ? ELSE metric_name END,
            metric_kind = CASE WHEN ? = 1 THEN ? ELSE metric_kind END,
            metric_unit = CASE WHEN ? = 1 THEN ? ELSE metric_unit END,
            observed_value = CASE WHEN ? = 1 THEN ? ELSE observed_value END,
            observed_numerator = CASE WHEN ? = 1 THEN ? ELSE observed_numerator END,
            observed_denominator = CASE WHEN ? = 1 THEN ? ELSE observed_denominator END,
            minimum_sample_count = CASE WHEN ? = 1 THEN ? ELSE minimum_sample_count END,
            minimum_numerator_count = CASE WHEN ? = 1 THEN ? ELSE minimum_numerator_count END,
            warning_threshold = CASE WHEN ? = 1 THEN ? ELSE warning_threshold END,
            critical_threshold = CASE WHEN ? = 1 THEN ? ELSE critical_threshold END,
            secondary_metric_name = CASE WHEN ? = 1 THEN ? ELSE secondary_metric_name END,
            secondary_metric_kind = CASE WHEN ? = 1 THEN ? ELSE secondary_metric_kind END,
            secondary_metric_unit = CASE WHEN ? = 1 THEN ? ELSE secondary_metric_unit END,
            secondary_observed_value = CASE WHEN ? = 1 THEN ? ELSE secondary_observed_value END,
            secondary_threshold = CASE WHEN ? = 1 THEN ? ELSE secondary_threshold END,
            consecutive_breaches = ?, breach_severity = ?, consecutive_clears = ?,
            current_severity = ?, generation = ?, revision = revision + 1,
            cooldown_until = ?, last_evaluated_at = ?,
            last_breached_at = CASE WHEN ? = 1 THEN ? ELSE last_breached_at END,
            last_cleared_at = CASE WHEN ? = 1 THEN ? ELSE last_cleared_at END,
            last_notification_scheduled_at = ?, updated_at = ?
      WHERE id = ? AND rule_id = ? AND environment = ? AND source_kind = ?
        AND dedupe_key = ? AND subject_ref IS ? AND hash_version IS ?
        AND queue_name IS ? AND revision = ? AND generation = ?
        AND last_evaluated_at = ? AND last_evaluated_at < ?
        AND revision < ? AND ${incidentPredicate}
        ${unknownGuard}`,
  );
  const evidenceValues: readonly (number | string | null)[] = [
    evidence?.windowSeconds ?? null,
    evidence?.metricName ?? null,
    evidence?.metricKind ?? null,
    evidence?.metricUnit ?? null,
    evidence?.observedValue ?? null,
    evidence?.observedNumerator ?? null,
    evidence?.observedDenominator ?? null,
    evidence?.minimumSampleCount ?? null,
    evidence?.minimumNumeratorCount ?? null,
    evidence?.warningThreshold ?? null,
    evidence?.criticalThreshold ?? null,
    evidence?.secondaryMetricName ?? null,
    evidence?.secondaryMetricKind ?? null,
    evidence?.secondaryMetricUnit ?? null,
    evidence?.secondaryObservedValue ?? null,
    evidence?.secondaryThreshold ?? null,
  ];
  const bindings: unknown[] = [];
  for (const value of evidenceValues) bindings.push(replaceEvidence, value);
  bindings.push(
    state.consecutiveBreaches,
    state.breachSeverity,
    state.consecutiveClears,
    state.status,
    options.generation,
    state.cooldownUntil,
    options.at,
    knownBreach,
    options.at,
    knownClear,
    options.at,
    state.lastNotificationAt,
    options.at,
    options.expected.stateId,
    options.ruleId,
    options.environment,
    options.sourceKind,
    options.dedupeKey,
    options.dimensions.subjectRef,
    options.dimensions.hashVersion,
    options.dimensions.queueName,
    options.expected.revision,
    options.expected.generation,
    options.expected.lastEvaluatedAt,
    options.at,
    MAX_STATE_REVISION,
  );
  if (options.expected.incident !== null) {
    if (options.expectedIncident === null) fail("invalid_input");
    bindings.push(
      options.expected.incident.id,
      options.expected.generation,
      options.expected.incident.status,
      options.expectedIncident.updatedAt,
    );
  }
  if (options.evaluation.evidence === "unknown") {
    bindings.push(state.status, options.expected.generation);
  }
  return statement.bind(...bindings);
}

function prepareImmediateConfirmation(
  database: D1Database,
  options: {
    at: string;
    environment: AlertEnvironment;
    ruleId: AlertRuleId;
    sourceKind: AlertSourceKind;
    stateId: string;
  },
): D1PreparedStatement {
  return database.prepare(
    `UPDATE alert_state
        SET current_severity = 'critical', generation = 1, revision = 1,
            consecutive_breaches = 0, breach_severity = NULL,
            consecutive_clears = 0, cooldown_until = NULL,
            last_notification_scheduled_at = ?, last_breached_at = ?,
            last_evaluated_at = ?, updated_at = ?
      WHERE id = ? AND rule_id = ? AND environment = ? AND source_kind = ?
        AND generation = 0 AND revision = 0 AND current_severity = 'none'
        AND breach_severity = 'critical' AND consecutive_breaches = 1
        AND changes() = 1`,
  ).bind(
    options.at,
    options.at,
    options.at,
    options.at,
    options.stateId,
    options.ruleId,
    options.environment,
    options.sourceKind,
  );
}

function prepareIncidentInsert(
  database: D1Database,
  incident: IncidentProjection,
): D1PreparedStatement {
  return database.prepare(
    `INSERT INTO security_alert
      (id, state_id, rule_id, environment, generation, severity, status,
       source_kind, first_seen_at, last_seen_at, window_seconds,
       metric_name, metric_kind, metric_unit, observed_value,
       observed_numerator, observed_denominator, minimum_sample_count,
       minimum_numerator_count, threshold, secondary_metric_name,
       secondary_metric_kind, secondary_metric_unit, secondary_observed_value,
       secondary_threshold, acknowledged_at, acknowledged_by_ref,
       acknowledged_by_hash_version, resolved_at, resolved_by_ref,
       resolved_by_hash_version, resolution_code, created_at, updated_at)
     SELECT ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?
      WHERE changes() = 1`,
  ).bind(
    incident.id,
    incident.stateId,
    incident.ruleId,
    incident.environment,
    incident.generation,
    incident.severity,
    incident.sourceKind,
    incident.firstSeenAt,
    incident.lastSeenAt,
    incident.windowSeconds,
    incident.metricName,
    incident.metricKind,
    incident.metricUnit,
    incident.observedValue,
    incident.observedNumerator,
    incident.observedDenominator,
    incident.minimumSampleCount,
    incident.minimumNumeratorCount,
    incident.threshold,
    incident.secondaryMetricName,
    incident.secondaryMetricKind,
    incident.secondaryMetricUnit,
    incident.secondaryObservedValue,
    incident.secondaryThreshold,
    incident.createdAt,
    incident.updatedAt,
  );
}

function prepareIncidentUpdate(
  database: D1Database,
  previous: IncidentProjection,
  next: IncidentProjection,
  resolveAt: string | null,
): D1PreparedStatement {
  return database.prepare(
    `UPDATE security_alert
        SET severity = ?, status = ?, last_seen_at = ?, window_seconds = ?,
            metric_name = ?, metric_kind = ?, metric_unit = ?, observed_value = ?,
            observed_numerator = ?, observed_denominator = ?,
            minimum_sample_count = ?, minimum_numerator_count = ?, threshold = ?,
            secondary_metric_name = ?, secondary_metric_kind = ?,
            secondary_metric_unit = ?, secondary_observed_value = ?,
            secondary_threshold = ?, resolved_at = ?, resolution_code = ?,
            updated_at = ?
      WHERE id = ? AND state_id = ? AND generation = ? AND status = ?
        AND severity = ? AND updated_at = ? AND changes() = 1`,
  ).bind(
    next.severity,
    next.status,
    next.lastSeenAt,
    next.windowSeconds,
    next.metricName,
    next.metricKind,
    next.metricUnit,
    next.observedValue,
    next.observedNumerator,
    next.observedDenominator,
    next.minimumSampleCount,
    next.minimumNumeratorCount,
    next.threshold,
    next.secondaryMetricName,
    next.secondaryMetricKind,
    next.secondaryMetricUnit,
    next.secondaryObservedValue,
    next.secondaryThreshold,
    resolveAt,
    resolveAt === null ? null : "healthy",
    next.updatedAt,
    previous.id,
    previous.stateId,
    previous.generation,
    previous.status,
    previous.severity,
    previous.updatedAt,
  );
}

function prepareOutboxInsert(
  database: D1Database,
  event: PlannedEvent,
  delivery: DeliverySnapshot,
  dimensions: DimensionColumns,
): D1PreparedStatement {
  const incident = event.incident;
  return database.prepare(
    `INSERT INTO alert_outbox
      (delivery_key, alert_id, generation, event_kind, event_sequence, channel,
       idempotency_key, payload_version, template_version, payload_json,
       payload_sha256, rule_id, environment, source_kind, severity,
       incident_status, subject_ref, hash_version, provider, queue_name, reason,
       surface, first_seen_at, last_seen_at, window_seconds, metric_name,
       metric_kind, metric_unit, observed_value, observed_numerator,
       observed_denominator, minimum_sample_count, minimum_numerator_count,
       threshold, secondary_metric_name, secondary_metric_kind,
       secondary_metric_unit, secondary_observed_value, secondary_threshold,
       status, attempts, replay_count, next_attempt_at, lease_id,
       lease_expires_at, accepted_at, dead_at, last_error_code,
       created_at, updated_at)
     SELECT ?, ?, ?, ?, ?, 'email', ?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            NULL, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, 'pending', 0, 0, ?, NULL, NULL, NULL, NULL, NULL, ?, ?
      WHERE changes() = 1`,
  ).bind(
    delivery.deliveryKey,
    incident.id,
    incident.generation,
    event.eventKind,
    event.eventSequence,
    delivery.idempotencyKey,
    delivery.payloadJson,
    delivery.payloadSha256,
    incident.ruleId,
    incident.environment,
    incident.sourceKind,
    event.severity,
    event.incidentStatus,
    dimensions.subjectRef,
    dimensions.hashVersion,
    dimensions.queueName,
    incident.firstSeenAt,
    incident.lastSeenAt,
    incident.windowSeconds,
    incident.metricName,
    incident.metricKind,
    incident.metricUnit,
    incident.observedValue,
    incident.observedNumerator,
    incident.observedDenominator,
    incident.minimumSampleCount,
    incident.minimumNumeratorCount,
    incident.threshold,
    incident.secondaryMetricName,
    incident.secondaryMetricKind,
    incident.secondaryMetricUnit,
    incident.secondaryObservedValue,
    incident.secondaryThreshold,
    delivery.createdAt,
    delivery.createdAt,
    delivery.createdAt,
  );
}

function prepareStateProjection(
  database: D1Database,
  options: {
    dimensions: DimensionColumns;
    environment: AlertEnvironment;
    ruleId: AlertRuleId;
    sourceKind: AlertSourceKind;
  },
): D1PreparedStatement {
  return database.prepare(
    `SELECT id, rule_id, environment, source_kind, dedupe_key,
            subject_ref, hash_version, queue_name, window_seconds,
            metric_name, metric_kind, metric_unit, observed_value,
            observed_numerator, observed_denominator, minimum_sample_count,
            minimum_numerator_count, warning_threshold, critical_threshold,
            secondary_metric_name, secondary_metric_kind, secondary_metric_unit,
            secondary_observed_value, secondary_threshold,
            consecutive_breaches, breach_severity, consecutive_clears,
            current_severity, generation, revision, cooldown_until,
            last_notification_scheduled_at, last_evaluated_at
       FROM alert_state
      WHERE rule_id = ? AND environment = ? AND source_kind = ?
        AND subject_ref IS ? AND queue_name IS ?`,
  ).bind(
    options.ruleId,
    options.environment,
    options.sourceKind,
    options.dimensions.subjectRef,
    options.dimensions.queueName,
  );
}

function prepareIncidentProjection(
  database: D1Database,
  options: {
    dimensions: DimensionColumns;
    environment: AlertEnvironment;
    ruleId: AlertRuleId;
    sourceKind: AlertSourceKind;
  },
  generation: number,
): D1PreparedStatement {
  return database.prepare(
    `SELECT ${INCIDENT_PROJECTION.split(",").map((column) =>
      `a.${column.trim()}`
    ).join(", ")}
       FROM security_alert AS a
       JOIN alert_state AS s ON s.id = a.state_id
      WHERE s.rule_id = ? AND s.environment = ? AND s.source_kind = ?
        AND s.subject_ref IS ? AND s.queue_name IS ? AND a.generation = ?`,
  ).bind(
    options.ruleId,
    options.environment,
    options.sourceKind,
    options.dimensions.subjectRef,
    options.dimensions.queueName,
    generation,
  );
}

function prepareOutboxProjection(
  database: D1Database,
  options: {
    dimensions: DimensionColumns;
    environment: AlertEnvironment;
    eventKind: PlannedEvent["eventKind"];
    generation: number;
    ruleId: AlertRuleId;
    sourceKind: AlertSourceKind;
  },
  at: string,
): D1PreparedStatement {
  const sequencePredicate = options.eventKind === "reminder"
    ? "o.created_at = ?"
    : "o.event_sequence = 1";
  const statement = database.prepare(
    `SELECT o.delivery_key, o.idempotency_key, o.payload_json, o.payload_sha256,
            o.event_kind, o.event_sequence, o.channel, o.created_at
       FROM alert_outbox AS o
       JOIN security_alert AS a ON a.id = o.alert_id
       JOIN alert_state AS s ON s.id = a.state_id
      WHERE s.rule_id = ? AND s.environment = ? AND s.source_kind = ?
        AND s.subject_ref IS ? AND s.queue_name IS ?
        AND o.generation = ? AND o.event_kind = ?
        AND ${sequencePredicate}`,
  );
  const bindings = [
    options.ruleId,
    options.environment,
    options.sourceKind,
    options.dimensions.subjectRef,
    options.dimensions.queueName,
    options.generation,
    options.eventKind,
  ];
  return options.eventKind === "reminder"
    ? statement.bind(...bindings, at)
    : statement.bind(...bindings);
}

function parseStateProjection(value: unknown): StateProjection {
  const record = recordValue(value);
  const ruleId = parseAlertRuleId(record.rule_id);
  const sourceKind = record.source_kind;
  const severity = record.current_severity;
  const breachSeverity = record.breach_severity;
  if (
    (sourceKind !== "d1_exact" && sourceKind !== "queue_approximate") ||
    (severity !== "none" && severity !== "warning" && severity !== "critical") ||
    (breachSeverity !== null && breachSeverity !== "warning" &&
      breachSeverity !== "critical")
  ) {
    fail("source_invalid");
  }
  return {
    breachSeverity,
    consecutiveBreaches: boundedInteger(record.consecutive_breaches, 0, 1),
    consecutiveClears: boundedInteger(record.consecutive_clears, 0, 4),
    cooldownUntil: nullableTimestamp(record.cooldown_until),
    criticalThreshold: record.critical_threshold === null
      ? null
      : boundedInteger(record.critical_threshold, 1, 1_000_000_000),
    currentSeverity: severity,
    dedupeKey: String(record.dedupe_key),
    environment: environment(record.environment),
    generation: boundedInteger(record.generation, 0, MAX_STATE_GENERATION),
    hashVersion: record.hash_version === null
      ? null
      : boundedInteger(record.hash_version, 1, 1),
    id: uuidV4(record.id),
    lastEvaluatedAt: canonicalTimestamp(record.last_evaluated_at).iso,
    lastNotificationScheduledAt: nullableTimestamp(
      record.last_notification_scheduled_at,
    ),
    metricKind: String(record.metric_kind) as AlertSelectedEvidence["kind"],
    metricName: String(record.metric_name) as AlertSelectedEvidence["metricName"],
    metricUnit: String(record.metric_unit) as AlertSelectedEvidence["unit"],
    minimumNumeratorCount: record.minimum_numerator_count === null
      ? null
      : Number(record.minimum_numerator_count),
    minimumSampleCount: Number(record.minimum_sample_count),
    observedDenominator: record.observed_denominator === null
      ? null
      : Number(record.observed_denominator),
    observedNumerator: record.observed_numerator === null
      ? null
      : Number(record.observed_numerator),
    observedValue: Number(record.observed_value),
    queueName: record.queue_name === null ? null : String(record.queue_name),
    revision: boundedInteger(record.revision, 0, MAX_STATE_REVISION),
    ruleId,
    secondaryMetricKind: record.secondary_metric_kind === null
      ? null
      : String(record.secondary_metric_kind) as AlertSelectedEvidence["kind"],
    secondaryMetricName: record.secondary_metric_name === null
      ? null
      : String(record.secondary_metric_name) as AlertSelectedEvidence["metricName"],
    secondaryMetricUnit: record.secondary_metric_unit === null
      ? null
      : String(record.secondary_metric_unit) as AlertSelectedEvidence["unit"],
    secondaryObservedValue: record.secondary_observed_value === null
      ? null
      : Number(record.secondary_observed_value),
    secondaryThreshold: record.secondary_threshold === null
      ? null
      : Number(record.secondary_threshold),
    sourceKind,
    subjectRef: record.subject_ref === null ? null : String(record.subject_ref),
    warningThreshold: record.warning_threshold === null
      ? null
      : boundedInteger(record.warning_threshold, 1, 1_000_000_000),
    windowSeconds: boundedInteger(record.window_seconds, 300, 3_600) as
      | 300
      | 900
      | 3_600,
  };
}

function stateMatches(
  row: StateProjection,
  options: {
    at: string;
    decision: AlertLifecycleResult;
    dedupeKey: string;
    dimensions: DimensionColumns;
    environment: AlertEnvironment;
    evidence: EvidenceColumns | null;
    generation: number;
    revision: number;
    ruleId: AlertRuleId;
    sourceKind: AlertSourceKind;
    stateId: string | null;
  },
): boolean {
  const state = options.decision.state;
  const evidenceMatches = options.evidence === null || (
    row.windowSeconds === options.evidence.windowSeconds &&
    row.metricName === options.evidence.metricName &&
    row.metricKind === options.evidence.metricKind &&
    row.metricUnit === options.evidence.metricUnit &&
    row.observedValue === options.evidence.observedValue &&
    row.observedNumerator === options.evidence.observedNumerator &&
    row.observedDenominator === options.evidence.observedDenominator &&
    row.minimumSampleCount === options.evidence.minimumSampleCount &&
    row.minimumNumeratorCount === options.evidence.minimumNumeratorCount &&
    row.warningThreshold === options.evidence.warningThreshold &&
    row.criticalThreshold === options.evidence.criticalThreshold &&
    row.secondaryMetricName === options.evidence.secondaryMetricName &&
    row.secondaryMetricKind === options.evidence.secondaryMetricKind &&
    row.secondaryMetricUnit === options.evidence.secondaryMetricUnit &&
    row.secondaryObservedValue === options.evidence.secondaryObservedValue &&
    row.secondaryThreshold === options.evidence.secondaryThreshold
  );
  return (options.stateId === null || row.id === options.stateId) &&
    row.ruleId === options.ruleId && row.environment === options.environment &&
    row.sourceKind === options.sourceKind && row.dedupeKey === options.dedupeKey &&
    row.subjectRef === options.dimensions.subjectRef &&
    row.hashVersion === options.dimensions.hashVersion &&
    row.queueName === options.dimensions.queueName &&
    row.currentSeverity === state.status &&
    row.breachSeverity === state.breachSeverity &&
    row.consecutiveBreaches === state.consecutiveBreaches &&
    row.consecutiveClears === state.consecutiveClears &&
    row.cooldownUntil === state.cooldownUntil &&
    row.lastNotificationScheduledAt === state.lastNotificationAt &&
    row.generation === options.generation && row.revision === options.revision &&
    row.lastEvaluatedAt === options.at && evidenceMatches;
}

function incidentMatches(left: IncidentProjection, right: IncidentProjection): boolean {
  return left.id === right.id && left.stateId === right.stateId &&
    left.ruleId === right.ruleId && left.environment === right.environment &&
    left.generation === right.generation && left.severity === right.severity &&
    left.status === right.status && left.sourceKind === right.sourceKind &&
    left.firstSeenAt === right.firstSeenAt && left.lastSeenAt === right.lastSeenAt &&
    left.windowSeconds === right.windowSeconds &&
    left.metricName === right.metricName && left.metricKind === right.metricKind &&
    left.metricUnit === right.metricUnit &&
    left.observedValue === right.observedValue &&
    left.observedNumerator === right.observedNumerator &&
    left.observedDenominator === right.observedDenominator &&
    left.minimumSampleCount === right.minimumSampleCount &&
    left.minimumNumeratorCount === right.minimumNumeratorCount &&
    left.threshold === right.threshold &&
    left.secondaryMetricName === right.secondaryMetricName &&
    left.secondaryMetricKind === right.secondaryMetricKind &&
    left.secondaryMetricUnit === right.secondaryMetricUnit &&
    left.secondaryObservedValue === right.secondaryObservedValue &&
    left.secondaryThreshold === right.secondaryThreshold;
}

function parseDeliveryProjection(value: unknown): DeliverySnapshot {
  const record = exactRecord(value, [
    "channel",
    "created_at",
    "delivery_key",
    "event_kind",
    "event_sequence",
    "idempotency_key",
    "payload_json",
    "payload_sha256",
  ]);
  const eventKind = record.event_kind;
  if (
    eventKind !== "opened" && eventKind !== "reminder" &&
    eventKind !== "escalated" && eventKind !== "resolved"
  ) {
    fail("source_invalid");
  }
  if (record.channel !== EMAIL_CHANNEL) fail("source_invalid");
  return {
    channel: EMAIL_CHANNEL,
    createdAt: canonicalTimestamp(record.created_at).iso,
    deliveryKey: String(record.delivery_key),
    eventKind,
    eventSequence: boundedInteger(record.event_sequence, 1, MAX_EVENT_SEQUENCE),
    idempotencyKey: String(record.idempotency_key),
    payloadJson: String(record.payload_json),
    payloadSha256: String(record.payload_sha256),
  };
}

async function canonicalDeliveryMatches(
  row: DeliverySnapshot,
  event: PlannedEvent,
  dimensions: DimensionColumns,
  at: string,
): Promise<boolean> {
  const exactEvent = { ...event, eventSequence: row.eventSequence };
  const expected = await deliverySnapshot(exactEvent, dimensions, at);
  return row.channel === expected.channel && row.createdAt === expected.createdAt &&
    row.deliveryKey === expected.deliveryKey && row.eventKind === expected.eventKind &&
    row.idempotencyKey === expected.idempotencyKey &&
    row.payloadJson === expected.payloadJson &&
    row.payloadSha256 === expected.payloadSha256;
}

function changesAt(results: D1Result[], index: number): number {
  const changes = results[index]?.meta.changes;
  return typeof changes === "number" ? changes : -1;
}

export async function persistAlertLifecycleDecision(
  database: D1Database,
  input: PersistAlertLifecycleDecisionInput,
): Promise<AlertStatePersistenceResult> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const record = exactRecord(input, [
      "decision",
      "environment",
      "evaluation",
      "expected",
    ]);
    const evaluation = normalizeEvaluation(record.evaluation);
    const decision = normalizeDecision(record.decision, evaluation);
    const environmentValue = environment(record.environment);
    const expected = normalizeExpectation(record.expected);
    const sourceKind = sourceKindFor(evaluation.ruleId);
    const dimensions = dimensionColumns(evaluation.dimension);
    const at = canonicalTimestamp(evaluation.asOf);

    if (decision.state.identity === null) {
      if (expected !== null || decision.intent !== null) fail("invalid_input");
      return "applied";
    }
    if (
      decision.state.lastEvaluatedAt !== at.iso ||
      !sameDimension(decision.state.identity.dimension, evaluation.dimension)
    ) {
      fail("invalid_input");
    }
    if (expected !== null && at.time <= canonicalTimestamp(expected.lastEvaluatedAt).time) {
      fail("invalid_input");
    }
    if (
      ALERT_RULE_DEFINITIONS[evaluation.ruleId].resolutionMode === "manual" &&
      decision.intent?.kind === "resolve"
    ) {
      fail("invalid_input");
    }
    const expectedIncident = expected === null
      ? null
      : await readExpectedIncident(
          database,
          expected,
          evaluation.ruleId,
          environmentValue,
          sourceKind,
        );
    if (
      expected !== null && expected.incident !== null &&
      expectedIncident === null
    ) {
      return "conflict";
    }
    if (
      expected !== null && expected.incident !== null &&
      expectedIncident !== null &&
      expectedIncident.status !== expected.incident.status &&
      !(
        decision.intent?.kind === "resolve" &&
        expectedIncident.status === "resolved" &&
        expectedIncident.updatedAt === at.iso
      )
    ) {
      return "conflict";
    }
    if (
      expectedIncident !== null &&
      canonicalTimestamp(expectedIncident.updatedAt).time > at.time
    ) {
      return "conflict";
    }
    const needsExpectedIncident = decision.intent !== null &&
      decision.intent.kind !== "open" ||
      (decision.state.phase === "active" && decision.intent?.kind !== "open");
    if (needsExpectedIncident && expectedIncident === null) fail("invalid_input");
    if (
      decision.intent?.kind === "open" &&
      expected !== null && expected.incident !== null
    ) {
      fail("invalid_input");
    }

    const evidence = persistedEvidence(decision.state, evaluation);
    const initialPositive = expected === null;
    if (initialPositive && (evidence === null || decision.state.status !== "none" &&
      !evaluation.immediateCritical)) {
      fail("invalid_input");
    }
    const immediateInitial = initialPositive && evaluation.immediateCritical;
    if (
      immediateInitial &&
      (decision.intent?.kind !== "open" || decision.state.status !== "critical")
    ) {
      fail("invalid_input");
    }
    const stateId = expected?.stateId ?? crypto.randomUUID();
    const initialAt = immediateInitial
      ? new Date(at.time - 1).toISOString()
      : at.iso;
    canonicalTimestamp(initialAt);
    const dedupeKey = await canonicalReference(
      "pgid.alert.state.v1",
      [
        evaluation.ruleId,
        environmentValue,
        sourceKind,
        evaluation.dimension.kind,
        dimensions.subjectRef ?? "",
        dimensions.queueName ?? "",
      ],
    );
    const nextGeneration = immediateInitial || decision.intent?.kind === "open"
      ? (expected?.generation ?? 0) + 1
      : expected?.generation ?? 0;
    const nextRevision = immediateInitial
      ? 1
      : expected === null ? 0 : expected.revision + 1;
    boundedInteger(nextGeneration, 0, MAX_STATE_GENERATION);
    boundedInteger(nextRevision, 0, MAX_STATE_REVISION);

    const statements: D1PreparedStatement[] = [];
    const expectedChanges: number[] = [];
    if (expected === null) {
      if (evidence === null) fail("invalid_input");
      statements.push(prepareStateInsert(database, {
        at: initialAt,
        dedupeKey,
        dimensions,
        environment: environmentValue,
        evidence,
        ruleId: evaluation.ruleId,
        sourceKind,
        stateId,
      }));
      expectedChanges.push(1);
      if (immediateInitial) {
        statements.push(prepareImmediateConfirmation(database, {
          at: at.iso,
          environment: environmentValue,
          ruleId: evaluation.ruleId,
          sourceKind,
          stateId,
        }));
        expectedChanges.push(1);
      }
    } else {
      statements.push(prepareStateUpdate(database, {
        at: at.iso,
        decision,
        dedupeKey,
        dimensions,
        environment: environmentValue,
        evaluation,
        expected,
        expectedIncident,
        evidence,
        generation: nextGeneration,
        ruleId: evaluation.ruleId,
        sourceKind,
      }));
      expectedChanges.push(1);
    }

    let desiredIncident: IncidentProjection | null = expectedIncident;
    let plannedEvent: PlannedEvent | null = null;
    const intent = decision.intent;
    if (intent?.kind === "open") {
      if (evidence === null) fail("invalid_input");
      desiredIncident = incidentFromEvidence({
        environment: environmentValue,
        evidence,
        firstSeenAt: at.iso,
        generation: nextGeneration,
        id: crypto.randomUUID(),
        lastSeenAt: at.iso,
        ruleId: evaluation.ruleId,
        severity: intent.severity,
        sourceKind,
        stateId,
      });
      statements.push(prepareIncidentInsert(database, desiredIncident));
      expectedChanges.push(1);
      plannedEvent = {
        eventKind: "opened",
        eventSequence: 1,
        incident: desiredIncident,
        incidentStatus: "open",
        severity: intent.severity,
      };
    } else if (intent?.kind === "escalate") {
      if (expectedIncident === null || evidence === null) fail("invalid_input");
      desiredIncident = incidentWithEvidence(
        expectedIncident,
        evidence,
        "critical",
        at.iso,
      );
      statements.push(
        prepareIncidentUpdate(database, expectedIncident, desiredIncident, null),
      );
      expectedChanges.push(1);
      plannedEvent = {
        eventKind: "escalated",
        eventSequence: 1,
        incident: desiredIncident,
        incidentStatus: desiredIncident.status,
        severity: "critical",
      };
    } else if (intent?.kind === "resolve") {
      if (expectedIncident === null) fail("invalid_input");
      desiredIncident = {
        ...expectedIncident,
        status: "resolved",
        updatedAt: at.iso,
      };
      statements.push(
        prepareIncidentUpdate(database, expectedIncident, desiredIncident, at.iso),
      );
      expectedChanges.push(1);
      plannedEvent = {
        eventKind: "resolved",
        eventSequence: 1,
        incident: desiredIncident,
        incidentStatus: "resolved",
        severity: intent.from,
      };
    } else {
      const refreshIncident = expectedIncident !== null &&
        decision.state.status !== "none" &&
        evaluation.evidence === "known" &&
        evaluation.severity === decision.state.status;
      if (refreshIncident) {
        if (evidence === null || expectedIncident === null) fail("invalid_input");
        desiredIncident = incidentWithEvidence(
          expectedIncident,
          evidence,
          decision.state.status as ActiveSeverity,
          at.iso,
        );
        statements.push(
          prepareIncidentUpdate(database, expectedIncident, desiredIncident, null),
        );
        expectedChanges.push(1);
      }
      if (intent?.kind === "remind") {
        if (desiredIncident === null) fail("invalid_input");
        const eventSequence = await nextReminderSequence(database, desiredIncident);
        plannedEvent = {
          eventKind: "reminder",
          eventSequence,
          incident: desiredIncident,
          incidentStatus: desiredIncident.status,
          severity: intent.severity,
        };
      }
    }

    let candidateDelivery: DeliverySnapshot | null = null;
    if (plannedEvent !== null) {
      candidateDelivery = await deliverySnapshot(plannedEvent, dimensions, at.iso);
      statements.push(
        prepareOutboxInsert(database, plannedEvent, candidateDelivery, dimensions),
      );
      expectedChanges.push(1);
    }

    const stateProjectionIndex = statements.length;
    statements.push(prepareStateProjection(database, {
      dimensions,
      environment: environmentValue,
      ruleId: evaluation.ruleId,
      sourceKind,
    }));
    const incidentProjectionIndex = desiredIncident === null ? null : statements.length;
    if (desiredIncident !== null) {
      statements.push(
        prepareIncidentProjection(database, {
          dimensions,
          environment: environmentValue,
          ruleId: evaluation.ruleId,
          sourceKind,
        }, nextGeneration),
      );
    }
    const outboxProjectionIndex = plannedEvent === null ? null : statements.length;
    if (plannedEvent !== null) {
      statements.push(prepareOutboxProjection(database, {
        dimensions,
        environment: environmentValue,
        eventKind: plannedEvent.eventKind,
        generation: nextGeneration,
        ruleId: evaluation.ruleId,
        sourceKind,
      }, at.iso));
    }

    let results: D1Result[];
    try {
      results = await database.batch(statements);
    } catch (error) {
      throw redactedRepositoryError(error, "write_failed");
    }
    const writeChanges = expectedChanges.map((_, index) => changesAt(results, index));
    const allApplied = writeChanges.every(
      (changes, index) => changes === expectedChanges[index],
    );
    const allDuplicate = writeChanges.every((changes) => changes === 0);
    if (!allApplied && !allDuplicate) fail("write_failed");

    const stateRaw = results[stateProjectionIndex]?.results[0];
    if (stateRaw === undefined) return "conflict";
    let stateRow: StateProjection;
    try {
      stateRow = parseStateProjection(stateRaw);
    } catch (error) {
      throw redactedRepositoryError(error, "source_invalid");
    }
    if (!stateMatches(stateRow, {
      at: at.iso,
      decision,
      dedupeKey,
      dimensions,
      environment: environmentValue,
      evidence,
      generation: nextGeneration,
      revision: nextRevision,
      ruleId: evaluation.ruleId,
      sourceKind,
      stateId: expected?.stateId ?? null,
    })) {
      return "conflict";
    }

    if (desiredIncident !== null && incidentProjectionIndex !== null) {
      const incidentRaw = results[incidentProjectionIndex]?.results[0];
      if (incidentRaw === undefined) return "conflict";
      let persistedIncident: IncidentProjection;
      try {
        persistedIncident = parseIncidentProjection(incidentRaw);
      } catch (error) {
        throw redactedRepositoryError(error, "source_invalid");
      }
      const comparableIncident = allDuplicate && intent?.kind === "open"
        ? {
            ...desiredIncident,
            id: persistedIncident.id,
            stateId: persistedIncident.stateId,
          }
        : desiredIncident;
      if (!incidentMatches(persistedIncident, comparableIncident)) return "conflict";
      if (plannedEvent !== null) plannedEvent.incident = persistedIncident;
    }

    if (plannedEvent !== null && outboxProjectionIndex !== null) {
      const outboxRows = results[outboxProjectionIndex]?.results ?? [];
      if (outboxRows.length !== 1) return "conflict";
      let persistedDelivery: DeliverySnapshot;
      try {
        persistedDelivery = parseDeliveryProjection(outboxRows[0]);
      } catch (error) {
        throw redactedRepositoryError(error, "source_invalid");
      }
      if (!await canonicalDeliveryMatches(
        persistedDelivery,
        plannedEvent,
        dimensions,
        at.iso,
      )) {
        return "conflict";
      }
    }
    return allApplied ? "applied" : "duplicate";
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}
