import {
  ALERT_RUNTIME_SOURCE_QUERY,
  alertWindowsAt,
  parseAlertObservation,
  parseAlertRuntimeSourceCompleteness,
  type AlertRuleObservation,
} from "./alert-rules";

export const RUNTIME_HEALTH_ALERT_RULE_ID =
  "pgid.alert.runtime_health.v1" as const;

export type RuntimeHealthAlertObservation = Extract<
  AlertRuleObservation,
  { ruleId: typeof RUNTIME_HEALTH_ALERT_RULE_ID }
>;

export interface ReadRuntimeHealthAlertSourceInput {
  asOf: string;
}

export interface IncompleteRuntimeHealthAlertSource {
  dimensionKind: "global";
  ruleId: typeof RUNTIME_HEALTH_ALERT_RULE_ID;
}

export interface RuntimeHealthAlertSourceResult {
  // A caller must not apply lifecycle clears while this source is incomplete.
  incomplete: readonly IncompleteRuntimeHealthAlertSource[];
  observations: readonly RuntimeHealthAlertObservation[];
}

export type AlertRuntimeHealthSourceRepositoryErrorCode =
  | "invalid_input"
  | "source_invalid"
  | "source_unavailable";

export class AlertRuntimeHealthSourceRepositoryError extends Error {
  readonly code: AlertRuntimeHealthSourceRepositoryErrorCode;

  constructor(code: AlertRuntimeHealthSourceRepositoryErrorCode) {
    super(`Alert runtime-health source repository failed (${code})`);
    this.name = "AlertRuntimeHealthSourceRepositoryError";
    this.code = code;
  }
}

const MAX_EVIDENCE_VALUE = 1_000_000_000;

// All three subqueries are current-state/all-age projections. The existing
// status-first index makes the dead count covering, bounds pending/retry by
// next_attempt_at, and bounds processing by its schema-required null due time
// before applying lease_expires_at.
export const ALERT_RUNTIME_HEALTH_OUTBOX_QUERY = `WITH
current_dead AS (
  SELECT count(*) AS dead_outbox
    FROM alert_outbox INDEXED BY alert_outbox_due_idx
   WHERE status = 'dead'
),
pending_retry_due AS (
  SELECT count(*) AS pending_retry_due_count,
         min(next_attempt_at) AS pending_retry_oldest_due_at,
         max(next_attempt_at) AS pending_retry_newest_due_at
    FROM alert_outbox INDEXED BY alert_outbox_due_idx
   WHERE status IN ('pending', 'retry')
     AND next_attempt_at <= ?1
),
expired_processing AS (
  SELECT count(*) AS processing_due_count,
         min(lease_expires_at) AS processing_oldest_due_at,
         max(lease_expires_at) AS processing_newest_due_at
    FROM alert_outbox INDEXED BY alert_outbox_due_idx
   WHERE status = 'processing'
     AND next_attempt_at IS NULL
     AND lease_expires_at <= ?1
)
SELECT current_dead.dead_outbox AS dead_outbox,
       pending_retry_due.pending_retry_due_count AS pending_retry_due_count,
       pending_retry_due.pending_retry_oldest_due_at
         AS pending_retry_oldest_due_at,
       pending_retry_due.pending_retry_newest_due_at
         AS pending_retry_newest_due_at,
       expired_processing.processing_due_count AS processing_due_count,
       expired_processing.processing_oldest_due_at
         AS processing_oldest_due_at,
       expired_processing.processing_newest_due_at
         AS processing_newest_due_at
  FROM current_dead, pending_retry_due, expired_processing`;

const OUTBOX_RESULT_KEYS = [
  "dead_outbox",
  "pending_retry_due_count",
  "pending_retry_oldest_due_at",
  "pending_retry_newest_due_at",
  "processing_due_count",
  "processing_oldest_due_at",
  "processing_newest_due_at",
] as const;

type UnknownRecord = Record<string, unknown>;

interface ParsedCount {
  overflow: boolean;
  value: number;
}

interface ParsedOutboxProjection {
  deadOutbox: number;
  outboxDueAgeSeconds: number | null;
  overflow: boolean;
}

function fail(code: AlertRuntimeHealthSourceRepositoryErrorCode): never {
  throw new AlertRuntimeHealthSourceRepositoryError(code);
}

function isRepositoryErrorCode(
  value: unknown,
): value is AlertRuntimeHealthSourceRepositoryErrorCode {
  return value === "invalid_input" ||
    value === "source_invalid" ||
    value === "source_unavailable";
}

function exactLocalRepositoryErrorCode(
  error: unknown,
): AlertRuntimeHealthSourceRepositoryErrorCode | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  try {
    if (
      Object.getPrototypeOf(error) !==
        AlertRuntimeHealthSourceRepositoryError.prototype
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
  fallback: AlertRuntimeHealthSourceRepositoryErrorCode,
): AlertRuntimeHealthSourceRepositoryError {
  return new AlertRuntimeHealthSourceRepositoryError(
    exactLocalRepositoryErrorCode(error) ?? fallback,
  );
}

function recordValue(value: unknown): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("source_invalid");
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
    fail("source_invalid");
  }
  return record;
}

function parseInput(value: unknown): ReadRuntimeHealthAlertSourceInput {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("invalid_input");
  }
  const record = value as UnknownRecord;
  if (
    Object.keys(record).length !== 1 ||
    !Object.hasOwn(record, "asOf") ||
    typeof record.asOf !== "string"
  ) {
    fail("invalid_input");
  }
  try {
    alertWindowsAt(record.asOf);
  } catch {
    fail("invalid_input");
  }
  return { asOf: record.asOf };
}

function resultRow(
  results: readonly D1Result<Record<string, unknown>>[],
  index: number,
): UnknownRecord {
  const result = results[index];
  if (!result || result.success !== true || !Array.isArray(result.results)) {
    fail("source_invalid");
  }
  if (result.results.length !== 1) fail("source_invalid");
  return recordValue(result.results[0]);
}

function sourceCount(value: unknown): ParsedCount {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    fail("source_invalid");
  }
  return { overflow: value > MAX_EVIDENCE_VALUE, value };
}

function canonicalTimestamp(value: unknown): string {
  if (typeof value !== "string" || value.length !== 24) {
    fail("source_invalid");
  }
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    fail("source_invalid");
  }
  return value;
}

function dueRange(
  count: number,
  oldestValue: unknown,
  newestValue: unknown,
  asOf: string,
): string | null {
  if (count === 0) {
    if (oldestValue !== null || newestValue !== null) fail("source_invalid");
    return null;
  }
  const oldest = canonicalTimestamp(oldestValue);
  const newest = canonicalTimestamp(newestValue);
  if (oldest > newest || newest > asOf) fail("source_invalid");
  return oldest;
}

function parseOutboxProjection(
  value: unknown,
  asOf: string,
): ParsedOutboxProjection {
  const row = exactRecord(value, OUTBOX_RESULT_KEYS);
  const dead = sourceCount(row.dead_outbox);
  const pendingRetry = sourceCount(row.pending_retry_due_count);
  const processing = sourceCount(row.processing_due_count);
  const pendingRetryOldest = dueRange(
    pendingRetry.value,
    row.pending_retry_oldest_due_at,
    row.pending_retry_newest_due_at,
    asOf,
  );
  const processingOldest = dueRange(
    processing.value,
    row.processing_oldest_due_at,
    row.processing_newest_due_at,
    asOf,
  );
  const dueCount = pendingRetry.value + processing.value;
  if (!Number.isSafeInteger(dueCount)) fail("source_invalid");
  const oldestDueAt = pendingRetryOldest === null
    ? processingOldest
    : processingOldest === null
      ? pendingRetryOldest
      : pendingRetryOldest < processingOldest
        ? pendingRetryOldest
        : processingOldest;
  let outboxDueAgeSeconds: number | null = null;
  let ageOverflow = false;
  if (oldestDueAt !== null) {
    const age = Math.floor(
      (new Date(asOf).getTime() - new Date(oldestDueAt).getTime()) / 1_000,
    );
    if (!Number.isSafeInteger(age) || age < 0) fail("source_invalid");
    ageOverflow = age > MAX_EVIDENCE_VALUE;
    outboxDueAgeSeconds = age;
  }
  return {
    deadOutbox: dead.value,
    outboxDueAgeSeconds,
    overflow: dead.overflow || pendingRetry.overflow || processing.overflow ||
      dueCount > MAX_EVIDENCE_VALUE || ageOverflow,
  };
}

function incompleteResult(): RuntimeHealthAlertSourceResult {
  return {
    incomplete: [{
      dimensionKind: "global",
      ruleId: RUNTIME_HEALTH_ALERT_RULE_ID,
    }],
    observations: [],
  };
}

function runtimeObservation(value: unknown): RuntimeHealthAlertObservation {
  const observation = parseAlertObservation(value);
  if (observation.ruleId !== RUNTIME_HEALTH_ALERT_RULE_ID) {
    fail("source_invalid");
  }
  return observation;
}

export async function readRuntimeHealthAlertSource(
  database: D1Database,
  inputValue: ReadRuntimeHealthAlertSourceInput,
): Promise<RuntimeHealthAlertSourceResult> {
  if (arguments.length !== 2) {
    throw new AlertRuntimeHealthSourceRepositoryError("invalid_input");
  }
  let input: ReadRuntimeHealthAlertSourceInput;
  try {
    input = parseInput(inputValue);
  } catch (error) {
    throw redactedRepositoryError(error, "invalid_input");
  }

  let results: D1Result<Record<string, unknown>>[];
  try {
    results = await database.batch<Record<string, unknown>>([
      database.prepare(ALERT_RUNTIME_SOURCE_QUERY),
      database.prepare(ALERT_RUNTIME_HEALTH_OUTBOX_QUERY).bind(input.asOf),
    ]);
  } catch {
    throw new AlertRuntimeHealthSourceRepositoryError("source_unavailable");
  }

  try {
    if (results.length !== 2) fail("source_invalid");
    const runtime = parseAlertRuntimeSourceCompleteness(
      resultRow(results, 0),
      input.asOf,
    );
    const outbox = parseOutboxProjection(
      resultRow(results, 1),
      input.asOf,
    );
    if (runtime === null) return { incomplete: [], observations: [] };
    if (outbox.overflow) return incompleteResult();
    return {
      incomplete: [],
      observations: [runtimeObservation({
        asOf: input.asOf,
        dimension: { kind: "global" },
        ruleId: RUNTIME_HEALTH_ALERT_RULE_ID,
        snapshot: {
          deadOutbox: outbox.deadOutbox,
          evaluatorAgeSeconds: runtime.evaluatorAgeSeconds,
          outboxDueAgeSeconds: outbox.outboxDueAgeSeconds,
        },
      })],
    };
  } catch (error) {
    throw redactedRepositoryError(error, "source_invalid");
  }
}
