import {
  ALERT_HASH_KEY_SENTINEL_DOMAIN,
  deriveAlertHashKeyFingerprintV1,
} from "./alert-audit-source-repository";
import {
  alertWindowsAt,
  deriveAlertReferenceV1,
  isHashedAlertReference,
  parseAlertObservation,
  type AlertRuleObservation,
  type AlertWindowKey,
  type HashedAlertReference,
  type LogoutDeliveryCurrentSnapshot,
  type LogoutDeliveryWindowMetrics,
} from "./alert-rules";

export const LOGOUT_DELIVERY_ALERT_RULE_ID =
  "pgid.logout.delivery_health.v1" as const;

export type LogoutDeliveryAlertObservation = Extract<
  AlertRuleObservation,
  { ruleId: typeof LOGOUT_DELIVERY_ALERT_RULE_ID }
>;
export type AlertLogoutSourceEnvironment = "local" | "preview" | "production";

export interface ReadLogoutDeliveryAlertSourceInput {
  asOf: string;
  environment: AlertLogoutSourceEnvironment;
  hmacKeyBase64Url: string | null;
}

export interface IncompleteLogoutDeliveryAlertSource {
  dimensionKind: "client_hmac" | "global";
  ruleId: typeof LOGOUT_DELIVERY_ALERT_RULE_ID;
}

export interface LogoutDeliveryAlertSourceResult {
  // A caller must not apply lifecycle clears for an incomplete dimension kind.
  incomplete: readonly IncompleteLogoutDeliveryAlertSource[];
  observations: readonly LogoutDeliveryAlertObservation[];
}

export type AlertLogoutSourceRepositoryErrorCode =
  | "invalid_input"
  | "source_invalid"
  | "source_unavailable";

export class AlertLogoutSourceRepositoryError extends Error {
  readonly code: AlertLogoutSourceRepositoryErrorCode;

  constructor(code: AlertLogoutSourceRepositoryErrorCode) {
    super(`Alert logout source repository failed (${code})`);
    this.name = "AlertLogoutSourceRepositoryError";
    this.code = code;
  }
}

const MAX_EVIDENCE_COUNT = 1_000_000_000;
const MAX_RATIO_COUNT = 1_000_000;
const MAX_DIMENSION_GROUPS = 1_000;
const DIMENSION_QUERY_LIMIT = MAX_DIMENSION_GROUPS + 1;
const WINDOW_KEYS = ["5m", "15m", "60m"] as const;
const ELIGIBLE_STATUSES =
  "'pending', 'processing', 'retry', 'delivered', 'dead'";
const UNRESOLVED_STATUSES = "'pending', 'processing', 'retry', 'dead'";
const TRACKED_LIFECYCLE_PREDICATE = `source_kind = 'd1_exact'
    AND subject_ref IS NOT NULL
    AND (
      current_severity <> 'none'
      OR breach_severity IS NOT NULL
      OR consecutive_breaches > 0
      OR consecutive_clears > 0
      OR cooldown_until IS NOT NULL
    )`;
const CANONICAL_CREATED_AT = `typeof(created_at) = 'text'
      AND length(created_at) = 24
      AND strftime('%Y-%m-%dT%H:%M:%fZ', created_at, '+0 seconds') IS NOT NULL
      AND strftime('%Y-%m-%dT%H:%M:%fZ', created_at, '+0 seconds') = created_at`;
const CANONICAL_COMPLETED_AT = `typeof(attempt.completed_at) = 'text'
      AND length(attempt.completed_at) = 24
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', attempt.completed_at, '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', attempt.completed_at, '+0 seconds'
      ) = attempt.completed_at`;

const SENTINEL_QUERY = `SELECT domain, fingerprint_ref, hash_version
FROM alert_hash_key_sentinel
WHERE id = 1`;

export const ALERT_LOGOUT_TIMESTAMP_INTEGRITY_QUERY = `SELECT
  EXISTS (
    SELECT 1
      FROM logout_delivery
      INDEXED BY logout_delivery_invalid_created_at_bounded_idx
     WHERE NOT (${CANONICAL_CREATED_AT})
     LIMIT 1
  ) AS invalid_delivery_timestamp_present,
  EXISTS (
    SELECT 1
      FROM logout_delivery_attempt AS attempt
      INDEXED BY logout_delivery_attempt_invalid_completed_at_bounded_idx
     WHERE attempt.completed_at IS NOT NULL
       AND NOT (${CANONICAL_COMPLETED_AT})
     LIMIT 1
  ) AS invalid_attempt_timestamp_present`;

export const ALERT_LOGOUT_TRACKED_DIMENSIONS_QUERY = `SELECT
  subject_ref, hash_version
FROM alert_state INDEXED BY alert_state_tracked_evaluation_idx
WHERE environment = ?
  AND rule_id = '${LOGOUT_DELIVERY_ALERT_RULE_ID}'
  AND ${TRACKED_LIFECYCLE_PREDICATE}
ORDER BY subject_ref
LIMIT ${DIMENSION_QUERY_LIMIT}`;

const CURRENT_PROJECTION = `count(*) AS current_unresolved,
  coalesce(sum(CASE WHEN status = 'dead' THEN 1 ELSE 0 END), 0)
    AS current_dead,
  min(created_at) AS oldest_unresolved_created_at,
  max(created_at) AS newest_unresolved_created_at,
  coalesce(sum(CASE WHEN ${CANONICAL_CREATED_AT} THEN 0 ELSE 1 END), 0)
    AS invalid_created_at_count`;

export const ALERT_LOGOUT_CURRENT_GLOBAL_QUERY = `SELECT
  ${CURRENT_PROJECTION}
FROM logout_delivery
  INDEXED BY logout_delivery_status_client_time_bounded_idx
WHERE status IN (${UNRESOLVED_STATUSES})
  AND created_at < ?1`;

export const ALERT_LOGOUT_CURRENT_CLIENT_QUERY = `SELECT
  client_id,
  ${CURRENT_PROJECTION}
FROM logout_delivery
  INDEXED BY logout_delivery_status_client_time_bounded_idx
WHERE status IN (${UNRESOLVED_STATUSES})
  AND created_at < ?1
GROUP BY client_id
ORDER BY client_id
LIMIT ${DIMENSION_QUERY_LIMIT}`;

const DELIVERY_WINDOW_PROJECTION = `coalesce(sum(CASE
    WHEN created_at >= ?1 THEN 1 ELSE 0 END), 0) AS eligible_5m,
  coalesce(sum(CASE
    WHEN created_at >= ?1 AND status IN (${UNRESOLVED_STATUSES})
    THEN 1 ELSE 0 END), 0) AS unresolved_5m,
  coalesce(sum(CASE
    WHEN created_at >= ?2 THEN 1 ELSE 0 END), 0) AS eligible_15m,
  coalesce(sum(CASE
    WHEN created_at >= ?2 AND status IN (${UNRESOLVED_STATUSES})
    THEN 1 ELSE 0 END), 0) AS unresolved_15m,
  count(*) AS eligible_60m,
  coalesce(sum(CASE WHEN status IN (${UNRESOLVED_STATUSES})
    THEN 1 ELSE 0 END), 0) AS unresolved_60m,
  min(created_at) AS oldest_created_at,
  max(created_at) AS newest_created_at,
  coalesce(sum(CASE WHEN ${CANONICAL_CREATED_AT} THEN 0 ELSE 1 END), 0)
    AS invalid_created_at_count`;

export const ALERT_LOGOUT_DELIVERY_GLOBAL_QUERY = `SELECT
  ${DELIVERY_WINDOW_PROJECTION}
FROM logout_delivery
  INDEXED BY logout_delivery_time_client_status_bounded_idx
WHERE created_at >= ?3
  AND created_at < ?4
  AND status IN (${ELIGIBLE_STATUSES})`;

export const ALERT_LOGOUT_DELIVERY_CLIENT_QUERY = `SELECT
  client_id,
  ${DELIVERY_WINDOW_PROJECTION}
FROM logout_delivery
  INDEXED BY logout_delivery_time_client_status_bounded_idx
WHERE created_at >= ?3
  AND created_at < ?4
  AND status IN (${ELIGIBLE_STATUSES})
GROUP BY client_id
ORDER BY client_id
LIMIT ${DIMENSION_QUERY_LIMIT}`;

const LEASE_WINDOW_PROJECTION = `coalesce(sum(CASE
    WHEN attempt.completed_at >= ?1 THEN 1 ELSE 0 END), 0)
    AS lease_expired_5m,
  coalesce(sum(CASE
    WHEN attempt.completed_at >= ?2 THEN 1 ELSE 0 END), 0)
    AS lease_expired_15m,
  count(*) AS lease_expired_60m,
  min(attempt.completed_at) AS oldest_completed_at,
  max(attempt.completed_at) AS newest_completed_at,
  coalesce(sum(CASE WHEN ${CANONICAL_COMPLETED_AT} THEN 0 ELSE 1 END), 0)
    AS invalid_completed_at_count`;

export const ALERT_LOGOUT_LEASE_GLOBAL_QUERY = `SELECT
  ${LEASE_WINDOW_PROJECTION}
FROM logout_delivery_attempt AS attempt
  INDEXED BY logout_delivery_attempt_completion_bounded_idx
WHERE attempt.completed_at >= ?3
  AND attempt.completed_at < ?4
  AND attempt.outcome = 'lease_expired'`;

export const ALERT_LOGOUT_LEASE_CLIENT_QUERY = `SELECT
  delivery.client_id,
  ${LEASE_WINDOW_PROJECTION}
FROM logout_delivery_attempt AS attempt
  INDEXED BY logout_delivery_attempt_completion_bounded_idx
JOIN logout_delivery AS delivery ON delivery.id = attempt.delivery_id
WHERE attempt.completed_at >= ?3
  AND attempt.completed_at < ?4
  AND attempt.outcome = 'lease_expired'
GROUP BY delivery.client_id
ORDER BY delivery.client_id
LIMIT ${DIMENSION_QUERY_LIMIT}`;

export const ALERT_LOGOUT_SOURCE_RESULT_INDEX = {
  sentinel: 0,
  tracked: 1,
  timestampIntegrity: 2,
  currentGlobal: 3,
  currentClient: 4,
  deliveryGlobal: 5,
  deliveryClient: 6,
  leaseGlobal: 7,
  leaseClient: 8,
} as const;

type UnknownRecord = Record<string, unknown>;
type WindowValues = Record<AlertWindowKey, number>;
type WindowStarts = Readonly<Record<AlertWindowKey, string>>;

interface ParsedDeliveryWindows {
  eligible: WindowValues;
  unresolved: WindowValues;
}

function fail(code: AlertLogoutSourceRepositoryErrorCode): never {
  throw new AlertLogoutSourceRepositoryError(code);
}

function isRepositoryErrorCode(
  value: unknown,
): value is AlertLogoutSourceRepositoryErrorCode {
  return value === "invalid_input" ||
    value === "source_invalid" ||
    value === "source_unavailable";
}

function exactLocalRepositoryErrorCode(
  error: unknown,
): AlertLogoutSourceRepositoryErrorCode | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  try {
    if (
      Object.getPrototypeOf(error) !==
        AlertLogoutSourceRepositoryError.prototype
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
  fallback: AlertLogoutSourceRepositoryErrorCode,
): AlertLogoutSourceRepositoryError {
  return new AlertLogoutSourceRepositoryError(
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

function parseInput(value: unknown): ReadLogoutDeliveryAlertSourceInput {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("invalid_input");
  }
  const record = value as UnknownRecord;
  const keys = ["asOf", "environment", "hmacKeyBase64Url"] as const;
  if (
    Object.keys(record).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(record, key))
  ) {
    fail("invalid_input");
  }
  if (
    record.environment !== "local" &&
    record.environment !== "preview" &&
    record.environment !== "production"
  ) {
    fail("invalid_input");
  }
  if (
    record.hmacKeyBase64Url !== null &&
    typeof record.hmacKeyBase64Url !== "string"
  ) {
    fail("invalid_input");
  }
  if (typeof record.asOf !== "string") fail("invalid_input");
  try {
    alertWindowsAt(record.asOf);
  } catch {
    fail("invalid_input");
  }
  return {
    asOf: record.asOf,
    environment: record.environment,
    hmacKeyBase64Url: record.hmacKeyBase64Url,
  };
}

function resultRows(
  results: readonly D1Result<Record<string, unknown>>[],
  index: number,
): readonly UnknownRecord[] {
  const result = results[index];
  if (!result || result.success !== true || !Array.isArray(result.results)) {
    fail("source_invalid");
  }
  return result.results.map(recordValue);
}

function oneRow(
  results: readonly D1Result<Record<string, unknown>>[],
  index: number,
): UnknownRecord {
  const rows = resultRows(results, index);
  if (rows.length !== 1) fail("source_invalid");
  return rows[0];
}

async function sentinelKeyAvailable(
  rows: readonly UnknownRecord[],
  key: string | null,
): Promise<boolean> {
  if (rows.length === 0) return false;
  if (rows.length !== 1) fail("source_invalid");
  const row = exactRecord(rows[0], [
    "domain",
    "fingerprint_ref",
    "hash_version",
  ]);
  if (
    row.domain !== ALERT_HASH_KEY_SENTINEL_DOMAIN ||
    !isHashedAlertReference({
      keyVersion: row.hash_version,
      value: row.fingerprint_ref,
    })
  ) {
    fail("source_invalid");
  }
  if (key === null) return false;
  try {
    const expected = await deriveAlertHashKeyFingerprintV1(key);
    return expected.value === row.fingerprint_ref;
  } catch {
    return false;
  }
}

function sourceCount(value: unknown, maximum: number): number | null {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    fail("source_invalid");
  }
  return value > maximum ? null : value;
}

function canonicalTimestamp(value: unknown): string {
  if (typeof value !== "string") fail("source_invalid");
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    fail("source_invalid");
  }
  return value;
}

function requiredRawIdentity(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 512) {
    fail("source_invalid");
  }
  return value;
}

function storedReference(
  reference: unknown,
  version: unknown,
): HashedAlertReference {
  const candidate = { keyVersion: version, value: reference };
  if (!isHashedAlertReference(candidate)) fail("source_invalid");
  return candidate;
}

function timestampIntegrityValid(value: unknown): boolean {
  const row = exactRecord(value, [
    "invalid_delivery_timestamp_present",
    "invalid_attempt_timestamp_present",
  ]);
  const invalidDelivery = sourceCount(
    row.invalid_delivery_timestamp_present,
    1,
  );
  const invalidAttempt = sourceCount(
    row.invalid_attempt_timestamp_present,
    1,
  );
  if (invalidDelivery === null || invalidAttempt === null) {
    fail("source_invalid");
  }
  return invalidDelivery === 0 && invalidAttempt === 0;
}

function nondecreasing(values: readonly number[]): boolean {
  return values[0] <= values[1] && values[1] <= values[2];
}

function timestampRange(
  oldestValue: unknown,
  newestValue: unknown,
  count: number,
  startInclusive: string,
  end: string,
  endInclusive: boolean,
): { newest: string | null; oldest: string | null } {
  if (count === 0) {
    if (oldestValue !== null || newestValue !== null) fail("source_invalid");
    return { newest: null, oldest: null };
  }
  const oldest = canonicalTimestamp(oldestValue);
  const newest = canonicalTimestamp(newestValue);
  if (
    oldest < startInclusive ||
    oldest > newest ||
    (endInclusive ? newest > end : newest >= end)
  ) {
    fail("source_invalid");
  }
  return { newest, oldest };
}

function parseCurrentSnapshot(
  value: unknown,
  asOf: string,
): LogoutDeliveryCurrentSnapshot | null {
  const row = exactRecord(value, [
    "current_unresolved",
    "current_dead",
    "oldest_unresolved_created_at",
    "newest_unresolved_created_at",
    "invalid_created_at_count",
  ]);
  const currentUnresolved = sourceCount(
    row.current_unresolved,
    MAX_EVIDENCE_COUNT,
  );
  const currentDead = sourceCount(row.current_dead, MAX_EVIDENCE_COUNT);
  const invalidTimestampCount = sourceCount(
    row.invalid_created_at_count,
    MAX_EVIDENCE_COUNT,
  );
  if (
    currentUnresolved === null ||
    currentDead === null ||
    invalidTimestampCount === null
  ) {
    return null;
  }
  if (invalidTimestampCount !== 0 || currentDead > currentUnresolved) {
    fail("source_invalid");
  }
  const range = timestampRange(
    row.oldest_unresolved_created_at,
    row.newest_unresolved_created_at,
    currentUnresolved,
    "0000-01-01T00:00:00.000Z",
    asOf,
    false,
  );
  if (range.oldest === null) {
    return {
      currentDead,
      currentUnresolved,
      oldestUnresolvedAgeSeconds: null,
    };
  }
  const age = Math.floor(
    (new Date(asOf).getTime() - new Date(range.oldest).getTime()) / 1_000,
  );
  if (!Number.isSafeInteger(age) || age < 0 || age > MAX_EVIDENCE_COUNT) {
    return null;
  }
  return {
    currentDead,
    currentUnresolved,
    oldestUnresolvedAgeSeconds: age,
  };
}

function parseDeliveryWindows(
  value: unknown,
  starts: WindowStarts,
  asOf: string,
): ParsedDeliveryWindows | null {
  const row = exactRecord(value, [
    "eligible_5m",
    "unresolved_5m",
    "eligible_15m",
    "unresolved_15m",
    "eligible_60m",
    "unresolved_60m",
    "oldest_created_at",
    "newest_created_at",
    "invalid_created_at_count",
  ]);
  const eligibleValues = WINDOW_KEYS.map((window) =>
    sourceCount(row[`eligible_${window}`], MAX_RATIO_COUNT)
  );
  const unresolvedValues = WINDOW_KEYS.map((window) =>
    sourceCount(row[`unresolved_${window}`], MAX_RATIO_COUNT)
  );
  const invalidTimestampCount = sourceCount(
    row.invalid_created_at_count,
    MAX_EVIDENCE_COUNT,
  );
  if (
    eligibleValues.some((entry) => entry === null) ||
    unresolvedValues.some((entry) => entry === null) ||
    invalidTimestampCount === null
  ) {
    return null;
  }
  const eligible = eligibleValues as number[];
  const unresolved = unresolvedValues as number[];
  if (
    invalidTimestampCount !== 0 ||
    !nondecreasing(eligible) ||
    !nondecreasing(unresolved) ||
    unresolved.some((entry, index) => entry > eligible[index])
  ) {
    fail("source_invalid");
  }
  const range = timestampRange(
    row.oldest_created_at,
    row.newest_created_at,
    eligible[2],
    starts["60m"],
    asOf,
    false,
  );
  for (const [index, window] of WINDOW_KEYS.entries()) {
    const hasTimestampInWindow = range.newest !== null &&
      range.newest >= starts[window];
    if ((eligible[index] > 0) !== hasTimestampInWindow) {
      fail("source_invalid");
    }
  }
  return {
    eligible: {
      "5m": eligible[0],
      "15m": eligible[1],
      "60m": eligible[2],
    },
    unresolved: {
      "5m": unresolved[0],
      "15m": unresolved[1],
      "60m": unresolved[2],
    },
  };
}

function parseLeaseWindows(
  value: unknown,
  starts: WindowStarts,
  asOf: string,
): WindowValues | null {
  const row = exactRecord(value, [
    "lease_expired_5m",
    "lease_expired_15m",
    "lease_expired_60m",
    "oldest_completed_at",
    "newest_completed_at",
    "invalid_completed_at_count",
  ]);
  const values = WINDOW_KEYS.map((window) =>
    sourceCount(row[`lease_expired_${window}`], MAX_EVIDENCE_COUNT)
  );
  const invalidTimestampCount = sourceCount(
    row.invalid_completed_at_count,
    MAX_EVIDENCE_COUNT,
  );
  if (
    values.some((entry) => entry === null) ||
    invalidTimestampCount === null
  ) {
    return null;
  }
  const counts = values as number[];
  if (invalidTimestampCount !== 0 || !nondecreasing(counts)) {
    fail("source_invalid");
  }
  const range = timestampRange(
    row.oldest_completed_at,
    row.newest_completed_at,
    counts[2],
    starts["60m"],
    asOf,
    false,
  );
  for (const [index, window] of WINDOW_KEYS.entries()) {
    const hasTimestampInWindow = range.newest !== null &&
      range.newest >= starts[window];
    if ((counts[index] > 0) !== hasTimestampInWindow) {
      fail("source_invalid");
    }
  }
  return { "5m": counts[0], "15m": counts[1], "60m": counts[2] };
}

function parseTrackedReferences(rows: readonly UnknownRecord[]): Set<string> | null {
  if (rows.length > MAX_DIMENSION_GROUPS) return null;
  const references = new Set<string>();
  for (const value of rows) {
    const row = exactRecord(value, ["subject_ref", "hash_version"]);
    references.add(storedReference(row.subject_ref, row.hash_version).value);
  }
  return references;
}

function parseClientRows<T>(
  rows: readonly UnknownRecord[],
  metricKeys: readonly string[],
  parser: (row: UnknownRecord) => T | null,
): Map<string, T> | null {
  if (rows.length > MAX_DIMENSION_GROUPS) return null;
  const parsed = new Map<string, T>();
  for (const value of rows) {
    const row = exactRecord(value, ["client_id", ...metricKeys]);
    const clientId = requiredRawIdentity(row.client_id);
    if (parsed.has(clientId)) fail("source_invalid");
    const metricRow: UnknownRecord = {};
    for (const key of metricKeys) metricRow[key] = row[key];
    const metrics = parser(metricRow);
    if (metrics === null) return null;
    parsed.set(clientId, metrics);
  }
  return parsed;
}

function emptyCurrent(): LogoutDeliveryCurrentSnapshot {
  return {
    currentDead: 0,
    currentUnresolved: 0,
    oldestUnresolvedAgeSeconds: null,
  };
}

function emptyDeliveryWindows(): ParsedDeliveryWindows {
  return {
    eligible: { "5m": 0, "15m": 0, "60m": 0 },
    unresolved: { "5m": 0, "15m": 0, "60m": 0 },
  };
}

function emptyLeaseWindows(): WindowValues {
  return { "5m": 0, "15m": 0, "60m": 0 };
}

function asLogoutObservation(value: unknown): LogoutDeliveryAlertObservation {
  const observation = parseAlertObservation(value);
  if (observation.ruleId !== LOGOUT_DELIVERY_ALERT_RULE_ID) {
    fail("source_invalid");
  }
  return observation;
}

function buildObservation(
  asOf: string,
  dimension: LogoutDeliveryAlertObservation["dimension"],
  current: LogoutDeliveryCurrentSnapshot,
  delivery: ParsedDeliveryWindows,
  leaseExpired: WindowValues,
): LogoutDeliveryAlertObservation {
  const windows = {} as Record<AlertWindowKey, LogoutDeliveryWindowMetrics>;
  for (const window of WINDOW_KEYS) {
    windows[window] = {
      eligible: delivery.eligible[window],
      leaseExpired: leaseExpired[window],
      unresolved: delivery.unresolved[window],
    };
  }
  return asLogoutObservation({
    asOf,
    current,
    dimension,
    ruleId: LOGOUT_DELIVERY_ALERT_RULE_ID,
    windows,
  });
}

function sumClientValues<T>(
  values: Iterable<T>,
  select: (value: T) => number,
): number | null {
  let total = 0;
  for (const value of values) {
    total += select(value);
    if (!Number.isSafeInteger(total) || total > MAX_EVIDENCE_COUNT) return null;
  }
  return total;
}

function clientProjectionsMatchGlobal(
  global: LogoutDeliveryAlertObservation,
  currentByClient: ReadonlyMap<string, LogoutDeliveryCurrentSnapshot>,
  deliveryByClient: ReadonlyMap<string, ParsedDeliveryWindows>,
  leaseByClient: ReadonlyMap<string, WindowValues>,
): boolean {
  const currentUnresolved = sumClientValues(
    currentByClient.values(),
    (current) => current.currentUnresolved,
  );
  const currentDead = sumClientValues(
    currentByClient.values(),
    (current) => current.currentDead,
  );
  let oldestAge: number | null = null;
  for (const current of currentByClient.values()) {
    if (current.oldestUnresolvedAgeSeconds !== null) {
      oldestAge = oldestAge === null
        ? current.oldestUnresolvedAgeSeconds
        : Math.max(oldestAge, current.oldestUnresolvedAgeSeconds);
    }
  }
  if (
    currentUnresolved !== global.current.currentUnresolved ||
    currentDead !== global.current.currentDead ||
    oldestAge !== global.current.oldestUnresolvedAgeSeconds
  ) {
    return false;
  }
  for (const window of WINDOW_KEYS) {
    const eligible = sumClientValues(
      deliveryByClient.values(),
      (delivery) => delivery.eligible[window],
    );
    const unresolved = sumClientValues(
      deliveryByClient.values(),
      (delivery) => delivery.unresolved[window],
    );
    const leaseExpired = sumClientValues(
      leaseByClient.values(),
      (lease) => lease[window],
    );
    const expected = global.windows[window];
    if (
      eligible !== expected.eligible ||
      unresolved !== expected.unresolved ||
      leaseExpired !== expected.leaseExpired
    ) {
      return false;
    }
  }
  return true;
}

function addIncomplete(
  incomplete: Map<string, IncompleteLogoutDeliveryAlertSource>,
  dimensionKind: IncompleteLogoutDeliveryAlertSource["dimensionKind"],
): void {
  incomplete.set(dimensionKind, {
    dimensionKind,
    ruleId: LOGOUT_DELIVERY_ALERT_RULE_ID,
  });
}

const CURRENT_KEYS = [
  "current_unresolved",
  "current_dead",
  "oldest_unresolved_created_at",
  "newest_unresolved_created_at",
  "invalid_created_at_count",
] as const;
const DELIVERY_KEYS = [
  "eligible_5m",
  "unresolved_5m",
  "eligible_15m",
  "unresolved_15m",
  "eligible_60m",
  "unresolved_60m",
  "oldest_created_at",
  "newest_created_at",
  "invalid_created_at_count",
] as const;
const LEASE_KEYS = [
  "lease_expired_5m",
  "lease_expired_15m",
  "lease_expired_60m",
  "oldest_completed_at",
  "newest_completed_at",
  "invalid_completed_at_count",
] as const;

export async function readLogoutDeliveryAlertSource(
  database: D1Database,
  inputValue: ReadLogoutDeliveryAlertSourceInput,
): Promise<LogoutDeliveryAlertSourceResult> {
  if (arguments.length !== 2) {
    throw new AlertLogoutSourceRepositoryError("invalid_input");
  }
  let input: ReadLogoutDeliveryAlertSourceInput;
  try {
    input = parseInput(inputValue);
  } catch (error) {
    throw redactedRepositoryError(error, "invalid_input");
  }
  const windows = alertWindowsAt(input.asOf);
  const windowBindings = [
    windows[0].startInclusive,
    windows[1].startInclusive,
    windows[2].startInclusive,
    windows[0].endExclusive,
  ] as const;

  let results: D1Result<Record<string, unknown>>[];
  try {
    results = await database.batch<Record<string, unknown>>([
      database.prepare(SENTINEL_QUERY),
      database.prepare(ALERT_LOGOUT_TRACKED_DIMENSIONS_QUERY).bind(
        input.environment,
      ),
      database.prepare(ALERT_LOGOUT_TIMESTAMP_INTEGRITY_QUERY),
      database.prepare(ALERT_LOGOUT_CURRENT_GLOBAL_QUERY).bind(input.asOf),
      database.prepare(ALERT_LOGOUT_CURRENT_CLIENT_QUERY).bind(input.asOf),
      database.prepare(ALERT_LOGOUT_DELIVERY_GLOBAL_QUERY).bind(
        ...windowBindings,
      ),
      database.prepare(ALERT_LOGOUT_DELIVERY_CLIENT_QUERY).bind(
        ...windowBindings,
      ),
      database.prepare(ALERT_LOGOUT_LEASE_GLOBAL_QUERY).bind(
        ...windowBindings,
      ),
      database.prepare(ALERT_LOGOUT_LEASE_CLIENT_QUERY).bind(
        ...windowBindings,
      ),
    ]);
  } catch {
    throw new AlertLogoutSourceRepositoryError("source_unavailable");
  }

  try {
    if (results.length !== Object.keys(ALERT_LOGOUT_SOURCE_RESULT_INDEX).length) {
      fail("source_invalid");
    }
    const incomplete = new Map<
      string,
      IncompleteLogoutDeliveryAlertSource
    >();
    const observations: LogoutDeliveryAlertObservation[] = [];
    const sourceTimestampsValid = timestampIntegrityValid(
      oneRow(results, ALERT_LOGOUT_SOURCE_RESULT_INDEX.timestampIntegrity),
    );
    if (!sourceTimestampsValid) {
      addIncomplete(incomplete, "global");
      addIncomplete(incomplete, "client_hmac");
    }

    let globalObservation: LogoutDeliveryAlertObservation | null = null;
    try {
      if (!sourceTimestampsValid) throw new Error("source timestamps invalid");
      const current = parseCurrentSnapshot(
        oneRow(results, ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentGlobal),
        input.asOf,
      );
      const delivery = parseDeliveryWindows(
        oneRow(results, ALERT_LOGOUT_SOURCE_RESULT_INDEX.deliveryGlobal),
        {
          "5m": windows[0].startInclusive,
          "15m": windows[1].startInclusive,
          "60m": windows[2].startInclusive,
        },
        input.asOf,
      );
      const leaseExpired = parseLeaseWindows(
        oneRow(results, ALERT_LOGOUT_SOURCE_RESULT_INDEX.leaseGlobal),
        {
          "5m": windows[0].startInclusive,
          "15m": windows[1].startInclusive,
          "60m": windows[2].startInclusive,
        },
        input.asOf,
      );
      if (current === null || delivery === null || leaseExpired === null) {
        addIncomplete(incomplete, "global");
      } else {
        globalObservation = buildObservation(
          input.asOf,
          { kind: "global" },
          current,
          delivery,
          leaseExpired,
        );
        observations.push(globalObservation);
      }
    } catch {
      addIncomplete(incomplete, "global");
    }

    const keyAvailable = await sentinelKeyAvailable(
      resultRows(results, ALERT_LOGOUT_SOURCE_RESULT_INDEX.sentinel),
      input.hmacKeyBase64Url,
    );
    if (!sourceTimestampsValid) {
      addIncomplete(incomplete, "client_hmac");
    } else if (!keyAvailable || input.hmacKeyBase64Url === null) {
      addIncomplete(incomplete, "client_hmac");
    } else {
      const hmacKeyBase64Url = input.hmacKeyBase64Url;
      try {
        const tracked = parseTrackedReferences(
          resultRows(results, ALERT_LOGOUT_SOURCE_RESULT_INDEX.tracked),
        );
        const currentByClient = parseClientRows(
          resultRows(results, ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentClient),
          CURRENT_KEYS,
          (row) => {
            const current = parseCurrentSnapshot(row, input.asOf);
            if (current !== null && current.currentUnresolved === 0) {
              fail("source_invalid");
            }
            return current;
          },
        );
        const deliveryByClient = parseClientRows(
          resultRows(results, ALERT_LOGOUT_SOURCE_RESULT_INDEX.deliveryClient),
          DELIVERY_KEYS,
          (row) => {
            const delivery = parseDeliveryWindows(
              row,
              {
                "5m": windows[0].startInclusive,
                "15m": windows[1].startInclusive,
                "60m": windows[2].startInclusive,
              },
              input.asOf,
            );
            if (delivery !== null && delivery.eligible["60m"] === 0) {
              fail("source_invalid");
            }
            return delivery;
          },
        );
        const leaseByClient = parseClientRows(
          resultRows(results, ALERT_LOGOUT_SOURCE_RESULT_INDEX.leaseClient),
          LEASE_KEYS,
          (row) => {
            const lease = parseLeaseWindows(
              row,
              {
                "5m": windows[0].startInclusive,
                "15m": windows[1].startInclusive,
                "60m": windows[2].startInclusive,
              },
              input.asOf,
            );
            if (lease !== null && lease["60m"] === 0) {
              fail("source_invalid");
            }
            return lease;
          },
        );
        if (
          tracked === null ||
          currentByClient === null ||
          deliveryByClient === null ||
          leaseByClient === null
        ) {
          addIncomplete(incomplete, "client_hmac");
        } else if (
          globalObservation !== null &&
          !clientProjectionsMatchGlobal(
            globalObservation,
            currentByClient,
            deliveryByClient,
            leaseByClient,
          )
        ) {
          addIncomplete(incomplete, "global");
          addIncomplete(incomplete, "client_hmac");
        } else {
          const rawClients = new Set([
            ...currentByClient.keys(),
            ...deliveryByClient.keys(),
            ...leaseByClient.keys(),
          ]);
          if (rawClients.size > MAX_DIMENSION_GROUPS) {
            addIncomplete(incomplete, "client_hmac");
          } else {
            const rawByReference = new Map<string, string>();
            const observationByReference = new Map<
              string,
              LogoutDeliveryAlertObservation
            >();
            for (const rawClient of rawClients) {
              const reference = await deriveAlertReferenceV1(
                hmacKeyBase64Url,
                "client_hmac",
                rawClient,
              );
              const existingRaw = rawByReference.get(reference.value);
              if (existingRaw !== undefined && existingRaw !== rawClient) {
                fail("source_invalid");
              }
              rawByReference.set(reference.value, rawClient);
              observationByReference.set(reference.value, buildObservation(
                input.asOf,
                {
                  kind: "client_hmac",
                  reference,
                },
                currentByClient.get(rawClient) ?? emptyCurrent(),
                deliveryByClient.get(rawClient) ?? emptyDeliveryWindows(),
                leaseByClient.get(rawClient) ?? emptyLeaseWindows(),
              ));
            }
            for (const reference of tracked) {
              if (!observationByReference.has(reference)) {
                observationByReference.set(reference, buildObservation(
                  input.asOf,
                  {
                    kind: "client_hmac",
                    reference: { keyVersion: 1, value: reference },
                  },
                  emptyCurrent(),
                  emptyDeliveryWindows(),
                  emptyLeaseWindows(),
                ));
              }
            }
            if (observationByReference.size > MAX_DIMENSION_GROUPS) {
              addIncomplete(incomplete, "client_hmac");
            } else {
              observations.push(
                ...[...observationByReference.entries()]
                  .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
                  .map(([, observation]) => observation),
              );
            }
          }
        }
      } catch {
        addIncomplete(incomplete, "client_hmac");
      }
    }

    return {
      incomplete: ["global", "client_hmac"]
        .flatMap((kind) => {
          const source = incomplete.get(kind);
          return source ? [source] : [];
        }),
      observations: observations.filter((observation) =>
        !incomplete.has(observation.dimension.kind)
      ),
    };
  } catch (error) {
    throw redactedRepositoryError(error, "source_invalid");
  }
}
