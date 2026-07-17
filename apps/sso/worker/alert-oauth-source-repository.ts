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
  type OAuthClientReportWindowMetrics,
} from "./alert-rules";

export const OAUTH_ALERT_RULE_ID = "pgid.oauth.client_report.v1" as const;

export type OAuthAlertObservation = Extract<
  AlertRuleObservation,
  { ruleId: typeof OAUTH_ALERT_RULE_ID }
>;
export type AlertOAuthSourceEnvironment = "local" | "preview" | "production";

export interface ReadOAuthAlertSourceInput {
  asOf: string;
  environment: AlertOAuthSourceEnvironment;
  hmacKeyBase64Url: string | null;
}

export interface IncompleteOAuthAlertSource {
  dimensionKind: "client_hmac";
  ruleId: typeof OAUTH_ALERT_RULE_ID;
}

export interface OAuthAlertSourceResult {
  // A caller must not apply lifecycle clears while this rule is incomplete.
  incomplete: readonly IncompleteOAuthAlertSource[];
  observations: readonly OAuthAlertObservation[];
}

export type AlertOAuthSourceRepositoryErrorCode =
  | "invalid_input"
  | "source_invalid"
  | "source_unavailable";

export class AlertOAuthSourceRepositoryError extends Error {
  readonly code: AlertOAuthSourceRepositoryErrorCode;

  constructor(code: AlertOAuthSourceRepositoryErrorCode) {
    super(`Alert OAuth source repository failed (${code})`);
    this.name = "AlertOAuthSourceRepositoryError";
    this.code = code;
  }
}

const MAX_EVIDENCE_COUNT = 1_000_000_000;
const MAX_DIMENSION_GROUPS = 1_000;
const DIMENSION_QUERY_LIMIT = MAX_DIMENSION_GROUPS + 1;
const WINDOW_KEYS = ["5m", "15m", "60m"] as const;
const TRACKED_LIFECYCLE_PREDICATE = `source_kind = 'd1_exact'
    AND subject_ref IS NOT NULL
    AND (
      current_severity <> 'none'
      OR breach_severity IS NOT NULL
      OR consecutive_breaches > 0
      OR consecutive_clears > 0
      OR cooldown_until IS NOT NULL
    )`;

export const ALERT_OAUTH_TIMESTAMP_INTEGRITY_QUERY = `SELECT EXISTS (
  SELECT 1
  FROM oauth_client_report
    INDEXED BY oauth_client_report_invalid_created_at_idx
  WHERE NOT (
    typeof(created_at) = 'text'
    AND length(created_at) = 24
    AND strftime(
      '%Y-%m-%dT%H:%M:%fZ', created_at, '+0 seconds'
    ) IS NOT NULL
    AND strftime(
      '%Y-%m-%dT%H:%M:%fZ', created_at, '+0 seconds'
    ) = created_at
  )
  LIMIT 1
) AS invalid_timestamp_exists`;

const SENTINEL_QUERY = `SELECT domain, fingerprint_ref, hash_version
FROM alert_hash_key_sentinel
WHERE id = 1`;

export const ALERT_OAUTH_TRACKED_DIMENSIONS_QUERY = `SELECT
  subject_ref, hash_version
FROM alert_state INDEXED BY alert_state_tracked_evaluation_idx
WHERE environment = ?
  AND rule_id = '${OAUTH_ALERT_RULE_ID}'
  AND ${TRACKED_LIFECYCLE_PREDICATE}
ORDER BY subject_ref
LIMIT ${DIMENSION_QUERY_LIMIT}`;

export const ALERT_OAUTH_REPORT_GROUP_QUERY = `SELECT
  client_id,
  reporter_user_id,
  reporter_ref,
  reporter_ref_hash_version,
  coalesce(sum(CASE WHEN created_at >= ?1 THEN 1 ELSE 0 END), 0) AS count_5m,
  coalesce(sum(CASE WHEN created_at >= ?1 AND reason IN ('impersonation', 'phishing') THEN 1 ELSE 0 END), 0) AS high_risk_5m,
  coalesce(sum(CASE WHEN created_at >= ?2 THEN 1 ELSE 0 END), 0) AS count_15m,
  coalesce(sum(CASE WHEN created_at >= ?2 AND reason IN ('impersonation', 'phishing') THEN 1 ELSE 0 END), 0) AS high_risk_15m,
  count(*) AS count_60m,
  coalesce(sum(CASE WHEN reason IN ('impersonation', 'phishing') THEN 1 ELSE 0 END), 0) AS high_risk_60m
FROM oauth_client_report
  INDEXED BY oauth_client_report_time_client_reason_reporter_bounded_idx
WHERE created_at >= ?3
  AND created_at < ?4
GROUP BY client_id, reporter_user_id, reporter_ref, reporter_ref_hash_version
ORDER BY client_id, reporter_ref, reporter_user_id
LIMIT ${DIMENSION_QUERY_LIMIT}`;

type UnknownRecord = Record<string, unknown>;
type GroupWindowCounts = Readonly<{
  count: Readonly<Record<AlertWindowKey, number>>;
  highRiskCount: Readonly<Record<AlertWindowKey, number>>;
}>;

interface MutableClientMetrics {
  count: Record<AlertWindowKey, number>;
  highRiskCount: Record<AlertWindowKey, number>;
  reporterIncomplete: Record<AlertWindowKey, boolean>;
  reporterReferences: Record<AlertWindowKey, Set<string>>;
}

function fail(code: AlertOAuthSourceRepositoryErrorCode): never {
  throw new AlertOAuthSourceRepositoryError(code);
}

function isRepositoryErrorCode(
  value: unknown,
): value is AlertOAuthSourceRepositoryErrorCode {
  return value === "invalid_input" ||
    value === "source_invalid" ||
    value === "source_unavailable";
}

function exactLocalRepositoryErrorCode(
  error: unknown,
): AlertOAuthSourceRepositoryErrorCode | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  try {
    if (
      Object.getPrototypeOf(error) !== AlertOAuthSourceRepositoryError.prototype
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
  fallback: AlertOAuthSourceRepositoryErrorCode,
): AlertOAuthSourceRepositoryError {
  return new AlertOAuthSourceRepositoryError(
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

function parseInput(value: unknown): ReadOAuthAlertSourceInput {
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

function assertCanonicalTimestampSource(
  results: readonly D1Result<Record<string, unknown>>[],
  index: number,
): void {
  const rows = resultRows(results, index);
  if (rows.length !== 1) fail("source_invalid");
  const row = exactRecord(rows[0], ["invalid_timestamp_exists"]);
  if (row.invalid_timestamp_exists !== 0) fail("source_invalid");
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

function incompleteResult(
  observations: readonly OAuthAlertObservation[] = [],
): OAuthAlertSourceResult {
  return {
    incomplete: [{
      dimensionKind: "client_hmac",
      ruleId: OAUTH_ALERT_RULE_ID,
    }],
    observations,
  };
}

function sourceCount(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > MAX_EVIDENCE_COUNT
  ) {
    fail("source_invalid");
  }
  return value;
}

function nested(values: readonly number[]): boolean {
  return values[0] <= values[1] && values[1] <= values[2];
}

function parseGroupWindowCounts(row: UnknownRecord): GroupWindowCounts {
  const count = WINDOW_KEYS.map((window) =>
    sourceCount(row[`count_${window}`])
  );
  const highRiskCount = WINDOW_KEYS.map((window) =>
    sourceCount(row[`high_risk_${window}`])
  );
  if (
    count[2] === 0 ||
    !nested(count) ||
    !nested(highRiskCount) ||
    highRiskCount.some((value, index) => value > count[index])
  ) {
    fail("source_invalid");
  }
  return {
    count: { "5m": count[0], "15m": count[1], "60m": count[2] },
    highRiskCount: {
      "5m": highRiskCount[0],
      "15m": highRiskCount[1],
      "60m": highRiskCount[2],
    },
  };
}

function optionalRawIdentity(
  value: unknown,
): { valid: boolean; value: string | null } {
  if (value === null) return { valid: true, value: null };
  return typeof value === "string" && value.length >= 1 && value.length <= 512
    ? { valid: true, value }
    : { valid: false, value: null };
}

function requiredRawIdentity(value: unknown): string {
  const parsed = optionalRawIdentity(value);
  if (!parsed.valid || parsed.value === null) fail("source_invalid");
  return parsed.value;
}

function storedReference(
  reference: unknown,
  version: unknown,
): { valid: boolean; value: HashedAlertReference | null } {
  if (reference === null && version === null) {
    return { valid: true, value: null };
  }
  const candidate = { keyVersion: version, value: reference };
  return isHashedAlertReference(candidate)
    ? { valid: true, value: candidate }
    : { valid: false, value: null };
}

async function resolveReporterReference(
  key: string,
  row: UnknownRecord,
  rawByReference: Map<string, string>,
): Promise<HashedAlertReference | null> {
  const raw = optionalRawIdentity(row.reporter_user_id);
  const stored = storedReference(
    row.reporter_ref,
    row.reporter_ref_hash_version,
  );
  if (!raw.valid || !stored.valid) return null;
  if (raw.value === null) return stored.value;
  let derived: HashedAlertReference;
  try {
    derived = await deriveAlertReferenceV1(key, "reporter_hmac", raw.value);
  } catch {
    return null;
  }
  const existingRaw = rawByReference.get(derived.value);
  if (existingRaw !== undefined && existingRaw !== raw.value) {
    fail("source_invalid");
  }
  rawByReference.set(derived.value, raw.value);
  if (stored.value !== null && stored.value.value !== derived.value) return null;
  return stored.value ?? derived;
}

function emptyClientMetrics(): MutableClientMetrics {
  return {
    count: { "5m": 0, "15m": 0, "60m": 0 },
    highRiskCount: { "5m": 0, "15m": 0, "60m": 0 },
    reporterIncomplete: { "5m": false, "15m": false, "60m": false },
    reporterReferences: {
      "5m": new Set<string>(),
      "15m": new Set<string>(),
      "60m": new Set<string>(),
    },
  };
}

function addGroupCounts(
  target: MutableClientMetrics,
  source: GroupWindowCounts,
): void {
  for (const window of WINDOW_KEYS) {
    const count = target.count[window] + source.count[window];
    const highRiskCount = target.highRiskCount[window] +
      source.highRiskCount[window];
    if (
      count > MAX_EVIDENCE_COUNT ||
      highRiskCount > MAX_EVIDENCE_COUNT ||
      highRiskCount > count
    ) {
      fail("source_invalid");
    }
    target.count[window] = count;
    target.highRiskCount[window] = highRiskCount;
  }
}

function markReporterIncomplete(
  target: MutableClientMetrics,
  source: GroupWindowCounts,
): void {
  for (const window of WINDOW_KEYS) {
    if (source.count[window] > 0) target.reporterIncomplete[window] = true;
  }
}

function parseTrackedReferences(
  rows: readonly UnknownRecord[],
): Set<string> | null {
  if (rows.length > MAX_DIMENSION_GROUPS) return null;
  const references = new Set<string>();
  for (const value of rows) {
    const row = exactRecord(value, ["subject_ref", "hash_version"]);
    const reference = storedReference(row.subject_ref, row.hash_version);
    if (!reference.valid || reference.value === null) return null;
    references.add(reference.value.value);
  }
  return references;
}

function asOAuthObservation(value: unknown): OAuthAlertObservation {
  const observation = parseAlertObservation(value);
  if (observation.ruleId !== OAUTH_ALERT_RULE_ID) fail("source_invalid");
  return observation;
}

function observationMetrics(
  metrics: MutableClientMetrics,
  window: AlertWindowKey,
): OAuthClientReportWindowMetrics {
  const distinctReporters = metrics.reporterIncomplete[window]
    ? null
    : metrics.reporterReferences[window].size;
  if (distinctReporters !== null && distinctReporters > metrics.count[window]) {
    fail("source_invalid");
  }
  return {
    count: metrics.count[window],
    distinctReporters,
    highRiskCount: metrics.highRiskCount[window],
  };
}

export async function readOAuthAlertSource(
  database: D1Database,
  inputValue: ReadOAuthAlertSourceInput,
): Promise<OAuthAlertSourceResult> {
  if (arguments.length !== 2) {
    throw new AlertOAuthSourceRepositoryError("invalid_input");
  }
  let input: ReadOAuthAlertSourceInput;
  try {
    input = parseInput(inputValue);
  } catch (error) {
    throw redactedRepositoryError(error, "invalid_input");
  }
  const windows = alertWindowsAt(input.asOf);
  let results: D1Result<Record<string, unknown>>[];
  try {
    results = await database.batch<Record<string, unknown>>([
      database.prepare(ALERT_OAUTH_TIMESTAMP_INTEGRITY_QUERY),
      database.prepare(SENTINEL_QUERY),
      database.prepare(ALERT_OAUTH_TRACKED_DIMENSIONS_QUERY).bind(
        input.environment,
      ),
      database.prepare(ALERT_OAUTH_REPORT_GROUP_QUERY).bind(
        windows[0].startInclusive,
        windows[1].startInclusive,
        windows[2].startInclusive,
        windows[0].endExclusive,
      ),
    ]);
  } catch {
    throw new AlertOAuthSourceRepositoryError("source_unavailable");
  }

  try {
    if (results.length !== 4) fail("source_invalid");
    assertCanonicalTimestampSource(results, 0);
    const keyAvailable = await sentinelKeyAvailable(
      resultRows(results, 1),
      input.hmacKeyBase64Url,
    );
    if (!keyAvailable || input.hmacKeyBase64Url === null) {
      return incompleteResult();
    }
    const hmacKeyBase64Url = input.hmacKeyBase64Url;

    let tracked: Set<string> | null;
    let sourceRows: readonly UnknownRecord[] | null;
    try {
      tracked = parseTrackedReferences(resultRows(results, 2));
      sourceRows = resultRows(results, 3);
    } catch {
      tracked = null;
      sourceRows = null;
    }
    if (
      tracked === null ||
      sourceRows === null ||
      sourceRows.length > MAX_DIMENSION_GROUPS
    ) {
      return incompleteResult();
    }

    const metricsByClient = new Map<string, MutableClientMetrics>();
    const clientRawByReference = new Map<string, string>();
    const reporterRawByReference = new Map<string, string>();
    let reporterCoverageIncomplete = false;
    try {
      for (const value of sourceRows) {
        const row = exactRecord(value, [
          "client_id",
          "reporter_user_id",
          "reporter_ref",
          "reporter_ref_hash_version",
          "count_5m",
          "high_risk_5m",
          "count_15m",
          "high_risk_15m",
          "count_60m",
          "high_risk_60m",
        ]);
        const clientRaw = requiredRawIdentity(row.client_id);
        const group = parseGroupWindowCounts(row);
        const clientReference = await deriveAlertReferenceV1(
          hmacKeyBase64Url,
          "client_hmac",
          clientRaw,
        );
        const existingClientRaw = clientRawByReference.get(clientReference.value);
        if (existingClientRaw !== undefined && existingClientRaw !== clientRaw) {
          fail("source_invalid");
        }
        clientRawByReference.set(clientReference.value, clientRaw);
        const clientMetrics = metricsByClient.get(clientReference.value) ??
          emptyClientMetrics();
        addGroupCounts(clientMetrics, group);
        const reporterReference = await resolveReporterReference(
          hmacKeyBase64Url,
          row,
          reporterRawByReference,
        );
        if (reporterReference === null) {
          reporterCoverageIncomplete = true;
          markReporterIncomplete(clientMetrics, group);
        } else {
          for (const window of WINDOW_KEYS) {
            if (group.count[window] > 0) {
              clientMetrics.reporterReferences[window].add(
                reporterReference.value,
              );
            }
          }
        }
        metricsByClient.set(clientReference.value, clientMetrics);
      }
    } catch {
      return incompleteResult();
    }

    for (const reference of tracked) {
      if (!metricsByClient.has(reference)) {
        metricsByClient.set(reference, emptyClientMetrics());
      }
    }
    if (metricsByClient.size > MAX_DIMENSION_GROUPS) {
      return incompleteResult();
    }

    const observations: OAuthAlertObservation[] = [];
    try {
      for (const [reference, metrics] of metricsByClient) {
        observations.push(asOAuthObservation({
          asOf: input.asOf,
          dimension: {
            kind: "client_hmac",
            reference: { keyVersion: 1, value: reference },
          },
          ruleId: OAUTH_ALERT_RULE_ID,
          windows: {
            "5m": observationMetrics(metrics, "5m"),
            "15m": observationMetrics(metrics, "15m"),
            "60m": observationMetrics(metrics, "60m"),
          },
        }));
      }
    } catch {
      return incompleteResult();
    }
    observations.sort((left, right) =>
      left.dimension.reference.value < right.dimension.reference.value
        ? -1
        : left.dimension.reference.value > right.dimension.reference.value
        ? 1
        : 0
    );
    return reporterCoverageIncomplete
      ? incompleteResult(observations)
      : { incomplete: [], observations };
  } catch (error) {
    throw redactedRepositoryError(error, "source_invalid");
  }
}
