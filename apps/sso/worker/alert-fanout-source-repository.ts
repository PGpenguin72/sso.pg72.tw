import {
  alertWindowsAt,
  parseAlertObservation,
  type AlertRuleObservation,
} from "./alert-rules";

export const FANOUT_GAP_ALERT_RULE_ID =
  "pgid.security.fanout_gap.v1" as const;

export type FanoutGapAlertObservation = Extract<
  AlertRuleObservation,
  { ruleId: typeof FANOUT_GAP_ALERT_RULE_ID }
>;

export interface ReadFanoutGapAlertSourceInput {
  asOf: string;
}

export interface IncompleteFanoutGapAlertSource {
  dimensionKind: "global";
  ruleId: typeof FANOUT_GAP_ALERT_RULE_ID;
}

export interface FanoutGapAlertSourceResult {
  // A caller must not apply lifecycle clears while this rule is incomplete.
  incomplete: readonly IncompleteFanoutGapAlertSource[];
  observations: readonly FanoutGapAlertObservation[];
}

export type AlertFanoutSourceRepositoryErrorCode =
  | "invalid_input"
  | "source_invalid"
  | "source_unavailable";

export class AlertFanoutSourceRepositoryError extends Error {
  readonly code: AlertFanoutSourceRepositoryErrorCode;

  constructor(code: AlertFanoutSourceRepositoryErrorCode) {
    super(`Alert fan-out source repository failed (${code})`);
    this.name = "AlertFanoutSourceRepositoryError";
    this.code = code;
  }
}

const MAX_EVIDENCE_COUNT = 1_000_000_000;
const RESULT_KEYS = [
  "invalid_source_timestamp_count",
  "missing_older_than_15m_count",
  "missing_older_than_5m_count",
] as const;

export const ALERT_FANOUT_GAP_QUERY = `SELECT
  coalesce(sum(CASE
    WHEN marker.event_id IS NULL AND source.occurred_at < ?3 THEN 1
    ELSE 0
  END), 0) AS missing_older_than_15m_count,
  coalesce(sum(CASE
    WHEN marker.event_id IS NULL AND source.occurred_at < ?4 THEN 1
    ELSE 0
  END), 0) AS missing_older_than_5m_count,
  coalesce(sum(CASE
    WHEN typeof(source.occurred_at) = 'text'
      AND length(source.occurred_at) = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', source.occurred_at, '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', source.occurred_at, '+0 seconds'
      ) = source.occurred_at
    THEN 0 ELSE 1
  END), 0) AS invalid_source_timestamp_count
FROM audit_event AS source INDEXED BY audit_event_time_bounded_idx
LEFT JOIN security_event_delivery AS marker
  ON marker.event_id = source.id
WHERE source.occurred_at >= ?1
  AND source.occurred_at < ?2`;

type UnknownRecord = Record<string, unknown>;

interface ParsedCount {
  overflow: boolean;
  value: number;
}

function fail(code: AlertFanoutSourceRepositoryErrorCode): never {
  throw new AlertFanoutSourceRepositoryError(code);
}

function isRepositoryErrorCode(
  value: unknown,
): value is AlertFanoutSourceRepositoryErrorCode {
  return value === "invalid_input" ||
    value === "source_invalid" ||
    value === "source_unavailable";
}

function exactLocalRepositoryErrorCode(
  error: unknown,
): AlertFanoutSourceRepositoryErrorCode | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  try {
    if (
      Object.getPrototypeOf(error) !==
        AlertFanoutSourceRepositoryError.prototype
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
  fallback: AlertFanoutSourceRepositoryErrorCode,
): AlertFanoutSourceRepositoryError {
  return new AlertFanoutSourceRepositoryError(
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

function parseInput(value: unknown): ReadFanoutGapAlertSourceInput {
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

function sourceCount(value: unknown): ParsedCount {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    fail("source_invalid");
  }
  return { overflow: value > MAX_EVIDENCE_COUNT, value };
}

function resultRow(
  results: readonly D1Result<Record<string, unknown>>[],
): UnknownRecord {
  if (results.length !== 1) fail("source_invalid");
  const result = results[0];
  if (!result || result.success !== true || !Array.isArray(result.results)) {
    fail("source_invalid");
  }
  if (result.results.length !== 1) fail("source_invalid");
  return exactRecord(result.results[0], RESULT_KEYS);
}

function incompleteResult(): FanoutGapAlertSourceResult {
  return {
    incomplete: [{
      dimensionKind: "global",
      ruleId: FANOUT_GAP_ALERT_RULE_ID,
    }],
    observations: [],
  };
}

function fanoutObservation(value: unknown): FanoutGapAlertObservation {
  const observation = parseAlertObservation(value);
  if (observation.ruleId !== FANOUT_GAP_ALERT_RULE_ID) {
    fail("source_invalid");
  }
  return observation;
}

export async function readFanoutGapAlertSource(
  database: D1Database,
  inputValue: ReadFanoutGapAlertSourceInput,
): Promise<FanoutGapAlertSourceResult> {
  if (arguments.length !== 2) {
    throw new AlertFanoutSourceRepositoryError("invalid_input");
  }
  let input: ReadFanoutGapAlertSourceInput;
  try {
    input = parseInput(inputValue);
  } catch (error) {
    throw redactedRepositoryError(error, "invalid_input");
  }

  const windows = alertWindowsAt(input.asOf);
  let results: D1Result<Record<string, unknown>>[];
  try {
    results = await database.batch<Record<string, unknown>>([
      database.prepare(ALERT_FANOUT_GAP_QUERY).bind(
        windows[2].startInclusive,
        windows[0].endExclusive,
        windows[1].startInclusive,
        windows[0].startInclusive,
      ),
    ]);
  } catch {
    throw new AlertFanoutSourceRepositoryError("source_unavailable");
  }

  try {
    const row = resultRow(results);
    const invalidTimestampCount = sourceCount(
      row.invalid_source_timestamp_count,
    );
    if (invalidTimestampCount.value !== 0) fail("source_invalid");

    const missingOlderThan15m = sourceCount(
      row.missing_older_than_15m_count,
    );
    const missingOlderThan5m = sourceCount(
      row.missing_older_than_5m_count,
    );
    if (missingOlderThan15m.value > missingOlderThan5m.value) {
      fail("source_invalid");
    }
    if (missingOlderThan15m.overflow || missingOlderThan5m.overflow) {
      return incompleteResult();
    }

    return {
      incomplete: [],
      observations: [fanoutObservation({
        asOf: input.asOf,
        dimension: { kind: "global" },
        ruleId: FANOUT_GAP_ALERT_RULE_ID,
        snapshot: {
          missingOlderThan15mCount: missingOlderThan15m.value,
          missingOlderThan5mCount: missingOlderThan5m.value,
        },
      })],
    };
  } catch (error) {
    throw redactedRepositoryError(error, "source_invalid");
  }
}
