import {
  ALERT_QUEUE_COMPONENTS,
  ALERT_QUEUE_NAMES,
  parseAlertObservation,
  type AlertQueueName,
  type AlertRuleObservation,
  type QueueDepthSnapshot,
} from "./alert-rules";

export const QUEUE_METRICS_ALERT_RULE_ID =
  "pgid.queue.dlq_approximate.v1" as const;

export type QueueMetricsAlertObservation = Extract<
  AlertRuleObservation,
  { ruleId: typeof QUEUE_METRICS_ALERT_RULE_ID }
>;

export interface QueueMetricsProvider {
  metrics(): Promise<unknown>;
}

export type QueueMetricsClock = () => Date;

export interface ReadQueueMetricsAlertSourceInput {
  queueName: AlertQueueName;
}

export interface QueueMetricSample {
  backlogBytes: number;
  backlogCount: number;
  oldestMessageAgeSeconds: number;
  queueName: AlertQueueName;
  sampledAt: string;
}

export type QueueMetricPersistenceOutcome =
  | "committed"
  | "rejected"
  | "replayed";

export interface PersistQueueMetricSampleResult {
  outcome: QueueMetricPersistenceOutcome;
  snapshot: QueueDepthSnapshot | null;
}

export interface QueueMetricsAlertSourceResult {
  observation: QueueMetricsAlertObservation;
  persistence: "committed" | "replayed" | "unknown";
}

export type AlertQueueSourceRepositoryErrorCode =
  | "invalid_input"
  | "source_invalid"
  | "source_unavailable"
  | "write_failed";

export class AlertQueueSourceRepositoryError extends Error {
  readonly code: AlertQueueSourceRepositoryErrorCode;

  constructor(code: AlertQueueSourceRepositoryErrorCode) {
    super(`Alert Queue source repository failed (${code})`);
    this.name = "AlertQueueSourceRepositoryError";
    this.code = code;
  }
}

const MAX_BACKLOG_COUNT = 1_000_000_000;
const MAX_BACKLOG_BYTES = 1_000_000_000_000;
const MAX_OLDEST_MESSAGE_AGE_SECONDS = 1_000_000_000;
const MAX_CONSECUTIVE_NONZERO_SAMPLES = 1_000_000;
const MAX_REVISION = 1_000_000_000;
const MAX_LEASE_DURATION_MILLISECONDS = 300_000;
const SAMPLE_CADENCE_MILLISECONDS = 60_000;
const QUEUE_NAME_SET = new Set<string>(ALERT_QUEUE_NAMES);
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const ALERT_QUEUE_METRIC_SAMPLE_UPSERT = `INSERT INTO alert_runtime_status (
  component, metric_sampled_at, backlog_count, backlog_bytes,
  oldest_message_age_seconds, nonzero_since_at,
  consecutive_nonzero_samples, updated_at
) VALUES (
  ?1, ?2, ?3, ?4, ?5,
  CASE WHEN ?3 > 0 THEN ?2 ELSE NULL END,
  CASE WHEN ?3 > 0 THEN 1 ELSE 0 END,
  ?2
)
ON CONFLICT (component) DO UPDATE SET
  revision = alert_runtime_status.revision + 1,
  metric_sampled_at = excluded.metric_sampled_at,
  backlog_count = excluded.backlog_count,
  backlog_bytes = excluded.backlog_bytes,
  oldest_message_age_seconds = excluded.oldest_message_age_seconds,
  nonzero_since_at = CASE
    WHEN excluded.backlog_count = 0 THEN NULL
    WHEN alert_runtime_status.metric_sampled_at IS NOT NULL
      AND alert_runtime_status.backlog_count > 0
      AND excluded.metric_sampled_at = strftime(
        '%Y-%m-%dT%H:%M:%fZ',
        alert_runtime_status.metric_sampled_at,
        '+60 seconds'
      )
      THEN alert_runtime_status.nonzero_since_at
    ELSE excluded.metric_sampled_at
  END,
  consecutive_nonzero_samples = CASE
    WHEN excluded.backlog_count = 0 THEN 0
    WHEN alert_runtime_status.metric_sampled_at IS NOT NULL
      AND alert_runtime_status.backlog_count > 0
      AND excluded.metric_sampled_at = strftime(
        '%Y-%m-%dT%H:%M:%fZ',
        alert_runtime_status.metric_sampled_at,
        '+60 seconds'
      )
      THEN alert_runtime_status.consecutive_nonzero_samples + 1
    ELSE 1
  END,
  updated_at = excluded.updated_at
WHERE alert_runtime_status.revision < ${MAX_REVISION}
  AND alert_runtime_status.lease_id IS NULL
  AND alert_runtime_status.updated_at < excluded.updated_at
  AND (
    alert_runtime_status.metric_sampled_at IS NULL
    OR alert_runtime_status.metric_sampled_at < excluded.metric_sampled_at
  )`;

export const ALERT_QUEUE_METRIC_CHANGES_QUERY =
  "SELECT changes() AS changed";

export const ALERT_QUEUE_METRIC_PROJECTION_QUERY = `SELECT
  component, revision, lease_id, lease_expires_at, metric_sampled_at,
  backlog_count, backlog_bytes, oldest_message_age_seconds, nonzero_since_at,
  consecutive_nonzero_samples, updated_at
FROM alert_runtime_status
WHERE component = ?1`;

type UnknownRecord = Record<string, unknown>;

interface QueueMetricProjection {
  backlogBytes: number;
  backlogCount: number;
  component: string;
  consecutiveNonzeroSamples: number;
  leaseExpiresAt: string | null;
  leaseId: string | null;
  metricSampledAt: string;
  nonzeroSinceAt: string | null;
  oldestMessageAgeSeconds: number;
  revision: number;
  updatedAt: string;
}

function fail(code: AlertQueueSourceRepositoryErrorCode): never {
  throw new AlertQueueSourceRepositoryError(code);
}

function isRepositoryErrorCode(
  value: unknown,
): value is AlertQueueSourceRepositoryErrorCode {
  return value === "invalid_input" ||
    value === "source_invalid" ||
    value === "source_unavailable" ||
    value === "write_failed";
}

function exactLocalRepositoryErrorCode(
  error: unknown,
): AlertQueueSourceRepositoryErrorCode | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  try {
    if (
      Object.getPrototypeOf(error) !== AlertQueueSourceRepositoryError.prototype
    ) {
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
  fallback: AlertQueueSourceRepositoryErrorCode,
): AlertQueueSourceRepositoryError {
  return new AlertQueueSourceRepositoryError(
    exactLocalRepositoryErrorCode(error) ?? fallback,
  );
}

function recordValue(
  value: unknown,
  code: AlertQueueSourceRepositoryErrorCode,
): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(code);
  }
  return value as UnknownRecord;
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  code: AlertQueueSourceRepositoryErrorCode,
): UnknownRecord {
  const record = recordValue(value, code);
  const actual = Object.keys(record);
  if (
    actual.length !== keys.length ||
    keys.some((key) => !Object.hasOwn(record, key))
  ) {
    fail(code);
  }
  return record;
}

function queueName(value: unknown): AlertQueueName {
  if (typeof value !== "string" || !QUEUE_NAME_SET.has(value)) {
    fail("invalid_input");
  }
  return value as AlertQueueName;
}

function canonicalTimestamp(
  value: unknown,
  code: AlertQueueSourceRepositoryErrorCode,
): { iso: string; time: number } {
  if (typeof value !== "string") fail(code);
  const time = new Date(value).getTime();
  if (
    value.length !== 24 ||
    !Number.isFinite(time) ||
    new Date(time).toISOString() !== value
  ) {
    fail(code);
  }
  return { iso: value, time };
}

function clockTimestamp(clock: QueueMetricsClock): {
  iso: string;
  time: number;
} {
  let value: unknown;
  try {
    value = clock();
  } catch (error) {
    throw redactedRepositoryError(error, "source_unavailable");
  }
  if (!(value instanceof Date)) fail("source_invalid");
  const time = value.getTime();
  if (!Number.isFinite(time)) fail("source_invalid");
  return { iso: new Date(time).toISOString(), time };
}

function boundedInteger(
  value: unknown,
  maximum: number,
  code: AlertQueueSourceRepositoryErrorCode,
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    fail(code);
  }
  return value;
}

function parseInput(value: unknown): ReadQueueMetricsAlertSourceInput {
  const record = exactRecord(value, ["queueName"], "invalid_input");
  return { queueName: queueName(record.queueName) };
}

function parseSample(value: unknown): QueueMetricSample {
  const record = exactRecord(value, [
    "backlogBytes",
    "backlogCount",
    "oldestMessageAgeSeconds",
    "queueName",
    "sampledAt",
  ], "invalid_input");
  const backlogBytes = boundedInteger(
    record.backlogBytes,
    MAX_BACKLOG_BYTES,
    "invalid_input",
  );
  const backlogCount = boundedInteger(
    record.backlogCount,
    MAX_BACKLOG_COUNT,
    "invalid_input",
  );
  const oldestMessageAgeSeconds = boundedInteger(
    record.oldestMessageAgeSeconds,
    MAX_OLDEST_MESSAGE_AGE_SECONDS,
    "invalid_input",
  );
  if (
    backlogCount === 0 &&
    (backlogBytes !== 0 || oldestMessageAgeSeconds !== 0)
  ) {
    fail("invalid_input");
  }
  return {
    backlogBytes,
    backlogCount,
    oldestMessageAgeSeconds,
    queueName: queueName(record.queueName),
    sampledAt: canonicalTimestamp(record.sampledAt, "invalid_input").iso,
  };
}

function normalizeBindingMetrics(
  value: unknown,
  queue: AlertQueueName,
  sampledAt: { iso: string; time: number },
): QueueMetricSample | null {
  try {
    const record = recordValue(value, "source_invalid");
    const actualKeys = Object.keys(record);
    if (
      !Object.hasOwn(record, "backlogBytes") ||
      !Object.hasOwn(record, "backlogCount") ||
      actualKeys.some((key) =>
        key !== "backlogBytes" &&
        key !== "backlogCount" &&
        key !== "oldestMessageTimestamp"
      )
    ) {
      fail("source_invalid");
    }
    const backlogBytes = boundedInteger(
      record.backlogBytes,
      MAX_BACKLOG_BYTES,
      "source_invalid",
    );
    const backlogCount = boundedInteger(
      record.backlogCount,
      MAX_BACKLOG_COUNT,
      "source_invalid",
    );
    const oldest = record.oldestMessageTimestamp;
    if (backlogCount === 0) {
      if (backlogBytes !== 0 || oldest !== undefined) fail("source_invalid");
      return {
        backlogBytes,
        backlogCount,
        oldestMessageAgeSeconds: 0,
        queueName: queue,
        sampledAt: sampledAt.iso,
      };
    }
    if (!(oldest instanceof Date)) fail("source_invalid");
    const oldestTime = oldest.getTime();
    if (!Number.isFinite(oldestTime) || oldestTime > sampledAt.time) {
      fail("source_invalid");
    }
    const age = Math.floor((sampledAt.time - oldestTime) / 1_000);
    if (
      !Number.isSafeInteger(age) ||
      age < 0 ||
      age > MAX_OLDEST_MESSAGE_AGE_SECONDS
    ) {
      fail("source_invalid");
    }
    return {
      backlogBytes,
      backlogCount,
      oldestMessageAgeSeconds: age,
      queueName: queue,
      sampledAt: sampledAt.iso,
    };
  } catch {
    return null;
  }
}

function resultRows(
  results: readonly D1Result<Record<string, unknown>>[],
  index: number,
): readonly UnknownRecord[] {
  const result = results[index];
  if (!result || result.success !== true || !Array.isArray(result.results)) {
    fail("source_invalid");
  }
  return result.results.map((row) => recordValue(row, "source_invalid"));
}

function oneRow(
  results: readonly D1Result<Record<string, unknown>>[],
  index: number,
): UnknownRecord {
  const rows = resultRows(results, index);
  if (rows.length !== 1) fail("source_invalid");
  return rows[0];
}

function parseProjection(
  value: unknown,
  expectedComponent: string,
): QueueMetricProjection | null {
  const row = exactRecord(value, [
    "component",
    "revision",
    "lease_id",
    "lease_expires_at",
    "metric_sampled_at",
    "backlog_count",
    "backlog_bytes",
    "oldest_message_age_seconds",
    "nonzero_since_at",
    "consecutive_nonzero_samples",
    "updated_at",
  ], "source_invalid");
  if (row.component !== expectedComponent) fail("source_invalid");
  const revision = boundedInteger(
    row.revision,
    MAX_REVISION,
    "source_invalid",
  );
  const updatedAt = canonicalTimestamp(row.updated_at, "source_invalid");
  let leaseId: string | null = null;
  let leaseExpiresAt: string | null = null;
  if (row.lease_id !== null || row.lease_expires_at !== null) {
    if (
      typeof row.lease_id !== "string" ||
      !UUID_V4_PATTERN.test(row.lease_id) ||
      row.lease_expires_at === null
    ) {
      fail("source_invalid");
    }
    const expiresAt = canonicalTimestamp(
      row.lease_expires_at,
      "source_invalid",
    );
    if (
      expiresAt.time <= updatedAt.time ||
      expiresAt.time - updatedAt.time > MAX_LEASE_DURATION_MILLISECONDS
    ) {
      fail("source_invalid");
    }
    leaseId = row.lease_id;
    leaseExpiresAt = expiresAt.iso;
  }
  const metricValues = [
    row.metric_sampled_at,
    row.backlog_count,
    row.backlog_bytes,
    row.oldest_message_age_seconds,
    row.nonzero_since_at,
    row.consecutive_nonzero_samples,
  ];
  if (metricValues.every((entry) => entry === null)) return null;
  if (
    row.metric_sampled_at === null ||
    row.backlog_count === null ||
    row.backlog_bytes === null ||
    row.oldest_message_age_seconds === null ||
    row.consecutive_nonzero_samples === null
  ) {
    fail("source_invalid");
  }
  const metricSampledAt = canonicalTimestamp(
    row.metric_sampled_at,
    "source_invalid",
  );
  if (metricSampledAt.time > updatedAt.time) fail("source_invalid");
  const backlogCount = boundedInteger(
    row.backlog_count,
    MAX_BACKLOG_COUNT,
    "source_invalid",
  );
  const backlogBytes = boundedInteger(
    row.backlog_bytes,
    MAX_BACKLOG_BYTES,
    "source_invalid",
  );
  const oldestMessageAgeSeconds = boundedInteger(
    row.oldest_message_age_seconds,
    MAX_OLDEST_MESSAGE_AGE_SECONDS,
    "source_invalid",
  );
  const consecutiveNonzeroSamples = boundedInteger(
    row.consecutive_nonzero_samples,
    MAX_CONSECUTIVE_NONZERO_SAMPLES,
    "source_invalid",
  );
  if (backlogCount === 0) {
    if (
      backlogBytes !== 0 ||
      oldestMessageAgeSeconds !== 0 ||
      row.nonzero_since_at !== null ||
      consecutiveNonzeroSamples !== 0
    ) {
      fail("source_invalid");
    }
    return {
      backlogBytes,
      backlogCount,
      component: expectedComponent,
      consecutiveNonzeroSamples,
      leaseExpiresAt,
      leaseId,
      metricSampledAt: metricSampledAt.iso,
      nonzeroSinceAt: null,
      oldestMessageAgeSeconds,
      revision,
      updatedAt: updatedAt.iso,
    };
  }
  if (row.nonzero_since_at === null || consecutiveNonzeroSamples < 1) {
    fail("source_invalid");
  }
  const nonzeroSinceAt = canonicalTimestamp(
    row.nonzero_since_at,
    "source_invalid",
  );
  const expectedElapsed =
    (consecutiveNonzeroSamples - 1) * SAMPLE_CADENCE_MILLISECONDS;
  if (metricSampledAt.time - nonzeroSinceAt.time !== expectedElapsed) {
    fail("source_invalid");
  }
  return {
    backlogBytes,
    backlogCount,
    component: expectedComponent,
    consecutiveNonzeroSamples,
    leaseExpiresAt,
    leaseId,
    metricSampledAt: metricSampledAt.iso,
    nonzeroSinceAt: nonzeroSinceAt.iso,
    oldestMessageAgeSeconds,
    revision,
    updatedAt: updatedAt.iso,
  };
}

function snapshotFromProjection(
  projection: QueueMetricProjection,
): QueueDepthSnapshot {
  const oldestMessageTimestamp = projection.backlogCount === 0
    ? null
    : new Date(
      new Date(projection.metricSampledAt).getTime() -
        projection.oldestMessageAgeSeconds * 1_000,
    ).toISOString();
  return {
    backlogBytes: projection.backlogBytes,
    backlogCount: projection.backlogCount,
    consecutiveNonzeroSamples: projection.consecutiveNonzeroSamples,
    nonzeroSinceAt: projection.nonzeroSinceAt,
    oldestMessageTimestamp,
    sampledAt: projection.metricSampledAt,
  };
}

function projectionOwnsSample(
  projection: QueueMetricProjection | null,
  sample: QueueMetricSample,
): projection is QueueMetricProjection {
  return projection !== null &&
    projection.updatedAt === sample.sampledAt &&
    projection.leaseId === null &&
    projection.leaseExpiresAt === null &&
    projection.metricSampledAt === sample.sampledAt &&
    projection.backlogCount === sample.backlogCount &&
    projection.backlogBytes === sample.backlogBytes &&
    projection.oldestMessageAgeSeconds === sample.oldestMessageAgeSeconds;
}

function queueObservation(
  asOf: string,
  queue: AlertQueueName,
  snapshot: QueueDepthSnapshot,
): QueueMetricsAlertObservation {
  try {
    const observation = parseAlertObservation({
      asOf,
      dimension: { kind: "queue", queue },
      ruleId: QUEUE_METRICS_ALERT_RULE_ID,
      snapshot,
    });
    if (observation.ruleId !== QUEUE_METRICS_ALERT_RULE_ID) {
      fail("source_invalid");
    }
    return observation;
  } catch (error) {
    throw redactedRepositoryError(error, "source_invalid");
  }
}

function unknownObservation(
  asOf: string,
  queue: AlertQueueName,
): QueueMetricsAlertObservation {
  return queueObservation(asOf, queue, {
    backlogBytes: null,
    backlogCount: null,
    consecutiveNonzeroSamples: null,
    nonzeroSinceAt: null,
    oldestMessageTimestamp: null,
    sampledAt: null,
  });
}

export async function persistQueueMetricSample(
  database: D1Database,
  inputValue: QueueMetricSample,
): Promise<PersistQueueMetricSampleResult> {
  if (arguments.length !== 2) {
    throw new AlertQueueSourceRepositoryError("invalid_input");
  }
  let sample: QueueMetricSample;
  try {
    sample = parseSample(inputValue);
  } catch (error) {
    throw redactedRepositoryError(error, "invalid_input");
  }
  const component = ALERT_QUEUE_COMPONENTS[sample.queueName];
  let results: D1Result<Record<string, unknown>>[];
  try {
    results = await database.batch<Record<string, unknown>>([
      database.prepare(ALERT_QUEUE_METRIC_SAMPLE_UPSERT).bind(
        component,
        sample.sampledAt,
        sample.backlogCount,
        sample.backlogBytes,
        sample.oldestMessageAgeSeconds,
      ),
      database.prepare(ALERT_QUEUE_METRIC_CHANGES_QUERY),
      database.prepare(ALERT_QUEUE_METRIC_PROJECTION_QUERY).bind(component),
    ]);
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
  try {
    if (results.length !== 3) fail("source_invalid");
    const writeResult = results[0];
    if (!writeResult || writeResult.success !== true) fail("source_invalid");
    const changedRow = exactRecord(
      oneRow(results, 1),
      ["changed"],
      "source_invalid",
    );
    const changed = boundedInteger(changedRow.changed, 1, "source_invalid");
    const metaChanges = boundedInteger(
      writeResult.meta.changes,
      1,
      "source_invalid",
    );
    if (changed !== metaChanges) fail("source_invalid");
    const projection = parseProjection(oneRow(results, 2), component);
    const ownsSample = projectionOwnsSample(projection, sample);
    if (changed === 1) {
      if (!ownsSample) fail("source_invalid");
      return {
        outcome: "committed",
        snapshot: snapshotFromProjection(projection),
      };
    }
    return ownsSample
      ? { outcome: "replayed", snapshot: snapshotFromProjection(projection) }
      : { outcome: "rejected", snapshot: null };
  } catch (error) {
    throw redactedRepositoryError(error, "source_invalid");
  }
}

export async function readQueueMetricsAlertSource(
  database: D1Database,
  provider: QueueMetricsProvider,
  inputValue: ReadQueueMetricsAlertSourceInput,
  clock: QueueMetricsClock,
): Promise<QueueMetricsAlertSourceResult> {
  if (arguments.length !== 4) {
    throw new AlertQueueSourceRepositoryError("invalid_input");
  }
  let input: ReadQueueMetricsAlertSourceInput;
  try {
    input = parseInput(inputValue);
    if (
      typeof provider !== "object" ||
      provider === null ||
      typeof provider.metrics !== "function" ||
      typeof clock !== "function"
    ) {
      fail("invalid_input");
    }
  } catch (error) {
    throw redactedRepositoryError(error, "invalid_input");
  }

  let rawMetrics: unknown;
  let providerAvailable = true;
  try {
    rawMetrics = await provider.metrics();
  } catch {
    providerAvailable = false;
    rawMetrics = null;
  }
  const sampledAt = clockTimestamp(clock);
  if (!providerAvailable) {
    return {
      observation: unknownObservation(sampledAt.iso, input.queueName),
      persistence: "unknown",
    };
  }
  const sample = normalizeBindingMetrics(
    rawMetrics,
    input.queueName,
    sampledAt,
  );
  if (sample === null) {
    return {
      observation: unknownObservation(sampledAt.iso, input.queueName),
      persistence: "unknown",
    };
  }
  let persisted: PersistQueueMetricSampleResult;
  try {
    persisted = await persistQueueMetricSample(database, sample);
  } catch {
    return {
      observation: unknownObservation(sampledAt.iso, input.queueName),
      persistence: "unknown",
    };
  }
  if (persisted.snapshot === null || persisted.outcome === "rejected") {
    return {
      observation: unknownObservation(sampledAt.iso, input.queueName),
      persistence: "unknown",
    };
  }
  return {
    observation: queueObservation(
      sampledAt.iso,
      input.queueName,
      persisted.snapshot,
    ),
    persistence: persisted.outcome,
  };
}
