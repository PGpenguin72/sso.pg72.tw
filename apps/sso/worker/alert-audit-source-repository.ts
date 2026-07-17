import {
  alertWindowsAt,
  deriveAlertReferenceV1,
  isHashedAlertReference,
  parseAlertObservation,
  type AlertDimension,
  type AlertRuleObservation,
  type AlertWindowKey,
  type HashedAlertReference,
} from "./alert-rules";

export const AUDIT_ALERT_RULE_IDS = [
  "pgid.registration.rate_limited.v1",
  "pgid.registration.denied.v1",
  "pgid.registration.challenge_unavailable.v1",
  "pgid.registration.restricted_created.v1",
  "pgid.restricted.sensitive_denied.v1",
  "pgid.recovery.entry_abuse.v1",
  "pgid.recovery.passkey_failure.v1",
  "pgid.passkey.step_up_failure.v1",
  "pgid.admin.sensitive_activity.v1",
  "pgid.admin.directory_volume.v1",
] as const;

export type AuditAlertRuleId = (typeof AUDIT_ALERT_RULE_IDS)[number];
export type AuditAlertObservation = Extract<
  AlertRuleObservation,
  { ruleId: AuditAlertRuleId }
>;
export type AuditAlertDimensionKind = Extract<
  AlertDimension["kind"],
  "actor_hmac" | "global" | "subject_hmac"
>;
export type AlertAuditSourceEnvironment = "local" | "preview" | "production";

export interface ReadAuditAlertSourcesInput {
  asOf: string;
  environment: AlertAuditSourceEnvironment;
  hmacKeyBase64Url: string | null;
}

export interface IncompleteAuditAlertSource {
  dimensionKind: AuditAlertDimensionKind;
  ruleId: AuditAlertRuleId;
}

export interface AuditAlertSourceResult {
  incomplete: readonly IncompleteAuditAlertSource[];
  observations: readonly AuditAlertObservation[];
}

export type AlertAuditSourceRepositoryErrorCode =
  | "invalid_input"
  | "source_invalid"
  | "source_unavailable";

export class AlertAuditSourceRepositoryError extends Error {
  readonly code: AlertAuditSourceRepositoryErrorCode;

  constructor(code: AlertAuditSourceRepositoryErrorCode) {
    super(`Alert audit source repository failed (${code})`);
    this.name = "AlertAuditSourceRepositoryError";
    this.code = code;
  }
}

export const ALERT_HASH_KEY_SENTINEL_DOMAIN =
  "pgid.alert_subject_hash_key.v1" as const;
const ALERT_HASH_KEY_SENTINEL_SIGNING_INPUT =
  `pgid-alert-v1\0key_sentinel\0${ALERT_HASH_KEY_SENTINEL_DOMAIN}`;

const MAX_EVIDENCE_COUNT = 1_000_000_000;
const MAX_RATIO_FIELD = 1_000_000;
const MAX_DIMENSION_GROUPS = 1_000;
const DIMENSION_QUERY_LIMIT = MAX_DIMENSION_GROUPS + 1;
const HMAC_REFERENCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const WINDOW_KEYS = ["5m", "15m", "60m"] as const;

type UnknownRecord = Record<string, unknown>;
type CountWindows = Readonly<Record<AlertWindowKey, number>>;
type RatioWindows = Readonly<
  Record<AlertWindowKey, { denominator: number; numerator: number }>
>;
type RestrictedWindows = Readonly<
  Record<AlertWindowKey, { count: number; knownSurfaces: number }>
>;
type RecoveryEntryWindows = Readonly<
  Record<AlertWindowKey, { denied: number; rateLimited: number; started: number }>
>;
type AdminSensitiveWindows = Readonly<
  Record<AlertWindowKey, { protectedDenials: number; successes: number }>
>;

const HASHED_SOURCE_IDENTITIES = [
  ["pgid.restricted.sensitive_denied.v1", "subject_hmac"],
  ["pgid.recovery.passkey_failure.v1", "subject_hmac"],
  ["pgid.passkey.step_up_failure.v1", "subject_hmac"],
  ["pgid.admin.sensitive_activity.v1", "actor_hmac"],
  ["pgid.admin.directory_volume.v1", "actor_hmac"],
] as const satisfies readonly (readonly [
  AuditAlertRuleId,
  AuditAlertDimensionKind,
])[];

const SENTINEL_QUERY = `SELECT domain, fingerprint_ref, hash_version
FROM alert_hash_key_sentinel
WHERE id = 1`;

const TRACKED_AUDIT_RULE_IDS = [
  "pgid.restricted.sensitive_denied.v1",
  "pgid.recovery.passkey_failure.v1",
  "pgid.passkey.step_up_failure.v1",
  "pgid.admin.sensitive_activity.v1",
  "pgid.admin.directory_volume.v1",
] as const satisfies readonly AuditAlertRuleId[];

const TRACKED_LIFECYCLE_PREDICATE = `source_kind = 'd1_exact'
    AND subject_ref IS NOT NULL
    AND (
      current_severity <> 'none'
      OR breach_severity IS NOT NULL
      OR consecutive_breaches > 0
      OR consecutive_clears > 0
      OR cooldown_until IS NOT NULL
    )`;

export const ALERT_AUDIT_TIMESTAMP_INTEGRITY_QUERY = `SELECT EXISTS (
  SELECT 1
  FROM audit_event INDEXED BY audit_event_invalid_occurred_at_idx
  WHERE NOT (
    typeof(occurred_at) = 'text'
    AND length(occurred_at) = 24
    AND strftime(
      '%Y-%m-%dT%H:%M:%fZ', occurred_at, '+0 seconds'
    ) IS NOT NULL
    AND strftime(
      '%Y-%m-%dT%H:%M:%fZ', occurred_at, '+0 seconds'
    ) = occurred_at
  )
  LIMIT 1
) AS invalid_timestamp_exists`;

function trackedDimensionSelect(
  ruleId: (typeof TRACKED_AUDIT_RULE_IDS)[number],
): string {
  return `SELECT rule_id, subject_ref, hash_version
  FROM alert_state INDEXED BY alert_state_tracked_evaluation_idx
  WHERE environment = ?1
    AND rule_id = '${ruleId}'
    AND ${TRACKED_LIFECYCLE_PREDICATE}
  ORDER BY subject_ref
  LIMIT ${DIMENSION_QUERY_LIMIT}`;
}

export const ALERT_AUDIT_TRACKED_DIMENSIONS_QUERY =
  TRACKED_AUDIT_RULE_IDS.map((ruleId) =>
    `SELECT rule_id, subject_ref, hash_version
FROM (${trackedDimensionSelect(ruleId)})`
  ).join("\nUNION ALL\n") + "\nORDER BY rule_id, subject_ref";

function countQuery(where: string): string {
  return `SELECT
  coalesce(sum(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END), 0) AS count_5m,
  coalesce(sum(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END), 0) AS count_15m,
  count(*) AS count_60m
FROM audit_event
WHERE ${where}
  AND occurred_at >= ?
  AND occurred_at < ?`;
}

function ratioQuery(where: string, numeratorPredicate: string): string {
  return `SELECT
  coalesce(sum(CASE WHEN occurred_at >= ? AND ${numeratorPredicate} THEN 1 ELSE 0 END), 0) AS numerator_5m,
  coalesce(sum(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END), 0) AS denominator_5m,
  coalesce(sum(CASE WHEN occurred_at >= ? AND ${numeratorPredicate} THEN 1 ELSE 0 END), 0) AS numerator_15m,
  coalesce(sum(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END), 0) AS denominator_15m,
  coalesce(sum(CASE WHEN ${numeratorPredicate} THEN 1 ELSE 0 END), 0) AS numerator_60m,
  count(*) AS denominator_60m
FROM audit_event
WHERE ${where}
  AND occurred_at >= ?
  AND occurred_at < ?`;
}

function dimensionRatioQuery(
  where: string,
  numeratorPredicate: string,
): string {
  return `SELECT
  subject_id AS raw_identity,
  coalesce(sum(CASE WHEN occurred_at >= ? AND ${numeratorPredicate} THEN 1 ELSE 0 END), 0) AS numerator_5m,
  coalesce(sum(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END), 0) AS denominator_5m,
  coalesce(sum(CASE WHEN occurred_at >= ? AND ${numeratorPredicate} THEN 1 ELSE 0 END), 0) AS numerator_15m,
  coalesce(sum(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END), 0) AS denominator_15m,
  coalesce(sum(CASE WHEN ${numeratorPredicate} THEN 1 ELSE 0 END), 0) AS numerator_60m,
  count(*) AS denominator_60m
FROM audit_event
WHERE ${where}
  AND occurred_at >= ?
  AND occurred_at < ?
GROUP BY subject_id
ORDER BY subject_id
LIMIT ${DIMENSION_QUERY_LIMIT}`;
}

const REGISTRATION_RATE_LIMITED_QUERY = countQuery(
  "event_type = 'registration.rate_limited' AND outcome = 'denied'",
);
const REGISTRATION_DENIED_QUERY = countQuery(
  "event_type = 'registration.denied' AND outcome = 'denied'",
);
const REGISTRATION_RESTRICTED_CREATED_QUERY = countQuery(
  `event_type = 'user.created'
   AND outcome = 'success'
   AND json_type(metadata_json, '$.accessLevel') = 'text'
   AND json_extract(metadata_json, '$.accessLevel') = 'restricted'`,
);

const REGISTRATION_CHALLENGE_QUERY = ratioQuery(
  `(
    (event_type = 'registration.challenge_unavailable' AND outcome = 'failure')
    OR (event_type = 'registration.challenge_denied' AND outcome = 'denied')
    OR (event_type = 'registration.intent_created' AND outcome = 'success')
  )`,
  "event_type = 'registration.challenge_unavailable'",
);

const RECOVERY_PASSKEY_WHERE = `(
  (event_type = 'recovery.passkey_failed' AND outcome = 'denied')
  OR (event_type = 'recovery.completed' AND outcome = 'success')
)`;
const RECOVERY_PASSKEY_GLOBAL_QUERY = ratioQuery(
  RECOVERY_PASSKEY_WHERE,
  "event_type = 'recovery.passkey_failed'",
);
const RECOVERY_PASSKEY_DIMENSION_QUERY = dimensionRatioQuery(
  RECOVERY_PASSKEY_WHERE,
  "event_type = 'recovery.passkey_failed'",
);

const PASSKEY_STEP_UP_WHERE = `(
  (event_type = 'passkey.step_up_failed' AND outcome = 'denied')
  OR (event_type = 'passkey.step_up_succeeded' AND outcome = 'success')
)`;
const PASSKEY_STEP_UP_GLOBAL_QUERY = ratioQuery(
  PASSKEY_STEP_UP_WHERE,
  "event_type = 'passkey.step_up_failed'",
);
const PASSKEY_STEP_UP_DIMENSION_QUERY = dimensionRatioQuery(
  PASSKEY_STEP_UP_WHERE,
  "event_type = 'passkey.step_up_failed'",
);

const RESTRICTED_DENIAL_QUERY = `SELECT
  subject_id AS raw_identity,
  coalesce(sum(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END), 0) AS count_5m,
  count(DISTINCT CASE WHEN occurred_at >= ? THEN json_extract(metadata_json, '$.surface') END) AS surfaces_5m,
  coalesce(sum(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END), 0) AS count_15m,
  count(DISTINCT CASE WHEN occurred_at >= ? THEN json_extract(metadata_json, '$.surface') END) AS surfaces_15m,
  count(*) AS count_60m,
  count(DISTINCT json_extract(metadata_json, '$.surface')) AS surfaces_60m
FROM audit_event
WHERE event_type = 'account.restricted_action_denied'
  AND outcome = 'denied'
  AND json_type(metadata_json, '$.surface') = 'text'
  AND json_extract(metadata_json, '$.surface') IN (
    'provider_link', 'clients.manage', 'clients.manage_all', 'users.read',
    'users.invite', 'users.manage', 'users.assign_roles'
  )
  AND occurred_at >= ?
  AND occurred_at < ?
GROUP BY subject_id
ORDER BY subject_id
LIMIT ${DIMENSION_QUERY_LIMIT}`;

const RECOVERY_ENTRY_QUERY = `SELECT
  coalesce(sum(CASE WHEN occurred_at >= ? AND event_type = 'recovery.entry_denied' THEN 1 ELSE 0 END), 0) AS denied_5m,
  coalesce(sum(CASE WHEN occurred_at >= ? AND event_type = 'recovery.rate_limited' THEN 1 ELSE 0 END), 0) AS rate_limited_5m,
  coalesce(sum(CASE WHEN occurred_at >= ? AND event_type = 'recovery.started' THEN 1 ELSE 0 END), 0) AS started_5m,
  coalesce(sum(CASE WHEN occurred_at >= ? AND event_type = 'recovery.entry_denied' THEN 1 ELSE 0 END), 0) AS denied_15m,
  coalesce(sum(CASE WHEN occurred_at >= ? AND event_type = 'recovery.rate_limited' THEN 1 ELSE 0 END), 0) AS rate_limited_15m,
  coalesce(sum(CASE WHEN occurred_at >= ? AND event_type = 'recovery.started' THEN 1 ELSE 0 END), 0) AS started_15m,
  coalesce(sum(CASE WHEN event_type = 'recovery.entry_denied' THEN 1 ELSE 0 END), 0) AS denied_60m,
  coalesce(sum(CASE WHEN event_type = 'recovery.rate_limited' THEN 1 ELSE 0 END), 0) AS rate_limited_60m,
  coalesce(sum(CASE WHEN event_type = 'recovery.started' THEN 1 ELSE 0 END), 0) AS started_60m
FROM audit_event
WHERE (
    (event_type = 'recovery.rate_limited' AND outcome = 'denied')
    OR (event_type = 'recovery.entry_denied' AND outcome = 'denied')
    OR (event_type = 'recovery.started' AND outcome = 'success')
  )
  AND occurred_at >= ?
  AND occurred_at < ?`;

const ADMIN_SUCCESS_EVENTS_SQL = `
  'invitation.created',
  'logout_delivery.replayed',
  'oauth_client.created',
  'oauth_client.deleted',
  'oauth_client.disabled',
  'oauth_client.enabled',
  'oauth_client.secret_rotated',
  'oauth_client.trust_updated',
  'oauth_client.updated',
  'user.access_promoted',
  'user.access_restricted',
  'user.deleted',
  'user.reactivated',
  'user.role_changed',
  'user.sessions_revoked',
  'user.suspended'`;
const BOOTADMIN_PROTECTED_EVENTS_SQL = `
  'user.access_promoted',
  'user.access_restricted',
  'user.deleted',
  'user.reactivated',
  'user.role_changed',
  'user.sessions_revoked',
  'user.suspended'`;

const ADMIN_SENSITIVE_QUERY = `SELECT
  actor_user_id, actor_ref, actor_ref_hash_version,
  coalesce(sum(CASE WHEN occurred_at >= ? AND outcome = 'success' THEN 1 ELSE 0 END), 0) AS successes_5m,
  coalesce(sum(CASE WHEN occurred_at >= ? AND outcome = 'denied' THEN 1 ELSE 0 END), 0) AS protected_5m,
  coalesce(sum(CASE WHEN occurred_at >= ? AND outcome = 'success' THEN 1 ELSE 0 END), 0) AS successes_15m,
  coalesce(sum(CASE WHEN occurred_at >= ? AND outcome = 'denied' THEN 1 ELSE 0 END), 0) AS protected_15m,
  coalesce(sum(CASE WHEN outcome = 'success' THEN 1 ELSE 0 END), 0) AS successes_60m,
  coalesce(sum(CASE WHEN outcome = 'denied' THEN 1 ELSE 0 END), 0) AS protected_60m
FROM audit_event
WHERE (
    (outcome = 'success' AND event_type IN (${ADMIN_SUCCESS_EVENTS_SQL}))
    OR (
      outcome = 'denied'
      AND event_type IN (${BOOTADMIN_PROTECTED_EVENTS_SQL})
      AND json_type(metadata_json, '$.reason') = 'text'
      AND json_extract(metadata_json, '$.reason') = 'bootadmin_protected'
    )
  )
  AND occurred_at >= ?
  AND occurred_at < ?
GROUP BY actor_user_id, actor_ref, actor_ref_hash_version
ORDER BY actor_ref, actor_user_id
LIMIT ${DIMENSION_QUERY_LIMIT}`;

const ADMIN_DIRECTORY_QUERY = `SELECT
  actor_user_id, actor_ref, actor_ref_hash_version,
  coalesce(sum(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END), 0) AS count_5m,
  coalesce(sum(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END), 0) AS count_15m,
  count(*) AS count_60m
FROM audit_event
WHERE event_type = 'admin.users_listed'
  AND outcome = 'success'
  AND occurred_at >= ?
  AND occurred_at < ?
GROUP BY actor_user_id, actor_ref, actor_ref_hash_version
ORDER BY actor_ref, actor_user_id
LIMIT ${DIMENSION_QUERY_LIMIT}`;

const RESULT_INDEX = {
  timestampIntegrity: 0,
  sentinel: 1,
  tracked: 2,
  registrationRateLimited: 3,
  registrationDenied: 4,
  registrationChallenge: 5,
  registrationRestrictedCreated: 6,
  restrictedDenial: 7,
  recoveryEntry: 8,
  recoveryPasskeyGlobal: 9,
  recoveryPasskeyDimension: 10,
  passkeyStepUpGlobal: 11,
  passkeyStepUpDimension: 12,
  adminSensitive: 13,
  adminDirectory: 14,
} as const;

function fail(code: AlertAuditSourceRepositoryErrorCode): never {
  throw new AlertAuditSourceRepositoryError(code);
}

function isRepositoryErrorCode(
  value: unknown,
): value is AlertAuditSourceRepositoryErrorCode {
  return value === "invalid_input" ||
    value === "source_invalid" ||
    value === "source_unavailable";
}

function exactLocalRepositoryErrorCode(
  error: unknown,
): AlertAuditSourceRepositoryErrorCode | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  try {
    if (
      Object.getPrototypeOf(error) !== AlertAuditSourceRepositoryError.prototype
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
  fallback: AlertAuditSourceRepositoryErrorCode,
): AlertAuditSourceRepositoryError {
  return new AlertAuditSourceRepositoryError(
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

function parseInput(value: unknown): ReadAuditAlertSourcesInput {
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

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function decodeHmacKey(value: string): Uint8Array<ArrayBuffer> {
  if (!HMAC_REFERENCE_PATTERN.test(value)) {
    throw new Error("invalid alert hash key");
  }
  let bytes: Uint8Array<ArrayBuffer> | undefined;
  try {
    const decoded = atob(`${value.replaceAll("-", "+").replaceAll("_", "/") }=`);
    if (decoded.length !== 32) throw new Error("invalid alert hash key");
    bytes = new Uint8Array(decoded.length);
    for (let index = 0; index < decoded.length; index += 1) {
      bytes[index] = decoded.charCodeAt(index);
    }
    if (base64Url(bytes) !== value) throw new Error("invalid alert hash key");
    const result = bytes;
    bytes = undefined;
    return result;
  } finally {
    bytes?.fill(0);
  }
}

export async function deriveAlertHashKeyFingerprintV1(
  keyBase64Url: string,
): Promise<HashedAlertReference> {
  const keyBytes = decodeHmacKey(keyBase64Url);
  let signingInput: Uint8Array<ArrayBuffer> | undefined;
  try {
    signingInput = new TextEncoder().encode(ALERT_HASH_KEY_SENTINEL_SIGNING_INPUT);
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { hash: "SHA-256", name: "HMAC" },
      false,
      ["sign"],
    );
    const signature = await crypto.subtle.sign("HMAC", key, signingInput);
    return { keyVersion: 1, value: base64Url(new Uint8Array(signature)) };
  } finally {
    keyBytes.fill(0);
    signingInput?.fill(0);
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
  return result.results.map(recordValue);
}

function oneRow(
  results: readonly D1Result<Record<string, unknown>>[],
  index: number,
  keys: readonly string[],
): UnknownRecord {
  const rows = resultRows(results, index);
  if (rows.length !== 1) fail("source_invalid");
  return exactRecord(rows[0], keys);
}

function assertCanonicalTimestampSource(
  results: readonly D1Result<Record<string, unknown>>[],
  index: number,
): void {
  const row = oneRow(results, index, ["invalid_timestamp_exists"]);
  if (row.invalid_timestamp_exists !== 0) fail("source_invalid");
}

interface ParsedCount {
  overflow: boolean;
  value: number;
}

function sourceCount(
  value: unknown,
  maximum = MAX_EVIDENCE_COUNT,
): ParsedCount {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    fail("source_invalid");
  }
  return {
    overflow: value > maximum,
    value,
  };
}

function nestedCounts(values: readonly number[]): boolean {
  return values[0] <= values[1] && values[1] <= values[2];
}

function parseCountWindows(row: UnknownRecord): CountWindows | null {
  const exact = exactRecord(row, ["count_5m", "count_15m", "count_60m"]);
  const parsed = WINDOW_KEYS.map((window) =>
    sourceCount(exact[`count_${window}`])
  );
  if (parsed.some(({ overflow }) => overflow)) return null;
  const values = parsed.map(({ value }) => value);
  if (!nestedCounts(values)) fail("source_invalid");
  return { "5m": values[0], "15m": values[1], "60m": values[2] };
}

const RATIO_KEYS = [
  "numerator_5m",
  "denominator_5m",
  "numerator_15m",
  "denominator_15m",
  "numerator_60m",
  "denominator_60m",
] as const;

function parseRatioWindows(row: UnknownRecord): RatioWindows | null {
  const exact = exactRecord(row, RATIO_KEYS);
  const numerators = WINDOW_KEYS.map((window) =>
    sourceCount(exact[`numerator_${window}`], MAX_RATIO_FIELD)
  );
  const denominators = WINDOW_KEYS.map((window) =>
    sourceCount(exact[`denominator_${window}`], MAX_RATIO_FIELD)
  );
  if (
    numerators.some(({ overflow }) => overflow) ||
    denominators.some(({ overflow }) => overflow)
  ) {
    return null;
  }
  const numeratorValues = numerators.map(({ value }) => value);
  const denominatorValues = denominators.map(({ value }) => value);
  if (
    !nestedCounts(numeratorValues) ||
    !nestedCounts(denominatorValues) ||
    numeratorValues.some((value, index) => value > denominatorValues[index])
  ) {
    fail("source_invalid");
  }
  return {
    "5m": { numerator: numeratorValues[0], denominator: denominatorValues[0] },
    "15m": { numerator: numeratorValues[1], denominator: denominatorValues[1] },
    "60m": { numerator: numeratorValues[2], denominator: denominatorValues[2] },
  };
}

function parseRestrictedWindows(row: UnknownRecord): RestrictedWindows | null {
  const exact = exactRecord(row, [
    "raw_identity",
    "count_5m",
    "surfaces_5m",
    "count_15m",
    "surfaces_15m",
    "count_60m",
    "surfaces_60m",
  ]);
  const counts = WINDOW_KEYS.map((window) =>
    sourceCount(exact[`count_${window}`])
  );
  const surfaces = WINDOW_KEYS.map((window) =>
    sourceCount(exact[`surfaces_${window}`])
  );
  if (
    counts.some(({ overflow }) => overflow) ||
    surfaces.some(({ overflow }) => overflow)
  ) {
    return null;
  }
  const countValues = counts.map(({ value }) => value);
  const surfaceValues = surfaces.map(({ value }) => value);
  if (
    !nestedCounts(countValues) ||
    !nestedCounts(surfaceValues) ||
    surfaceValues.some((value, index) => value > countValues[index])
  ) {
    fail("source_invalid");
  }
  return {
    "5m": { count: countValues[0], knownSurfaces: surfaceValues[0] },
    "15m": { count: countValues[1], knownSurfaces: surfaceValues[1] },
    "60m": { count: countValues[2], knownSurfaces: surfaceValues[2] },
  };
}

function parseRecoveryEntryWindows(row: UnknownRecord): RecoveryEntryWindows | null {
  const keys = WINDOW_KEYS.flatMap((window) => [
    `denied_${window}`,
    `rate_limited_${window}`,
    `started_${window}`,
  ]);
  const exact = exactRecord(row, keys);
  const values = (
    prefix: "denied" | "rate_limited" | "started",
    maximum = MAX_EVIDENCE_COUNT,
  ) =>
    WINDOW_KEYS.map((window) =>
      sourceCount(exact[`${prefix}_${window}`], maximum)
    );
  const denied = values("denied", MAX_RATIO_FIELD);
  const rateLimited = values("rate_limited");
  const started = values("started", MAX_RATIO_FIELD);
  if (
    [...denied, ...rateLimited, ...started].some(({ overflow }) => overflow)
  ) {
    return null;
  }
  const deniedValues = denied.map(({ value }) => value);
  const rateLimitedValues = rateLimited.map(({ value }) => value);
  const startedValues = started.map(({ value }) => value);
  if (
    !nestedCounts(deniedValues) ||
    !nestedCounts(rateLimitedValues) ||
    !nestedCounts(startedValues)
  ) {
    fail("source_invalid");
  }
  if (
    deniedValues.some((value, index) =>
      value + startedValues[index] > MAX_RATIO_FIELD
    )
  ) {
    return null;
  }
  return {
    "5m": {
      denied: deniedValues[0],
      rateLimited: rateLimitedValues[0],
      started: startedValues[0],
    },
    "15m": {
      denied: deniedValues[1],
      rateLimited: rateLimitedValues[1],
      started: startedValues[1],
    },
    "60m": {
      denied: deniedValues[2],
      rateLimited: rateLimitedValues[2],
      started: startedValues[2],
    },
  };
}

function parseAdminSensitiveWindows(
  row: UnknownRecord,
): AdminSensitiveWindows | null {
  const exact = exactRecord(row, [
    "actor_user_id",
    "actor_ref",
    "actor_ref_hash_version",
    "successes_5m",
    "protected_5m",
    "successes_15m",
    "protected_15m",
    "successes_60m",
    "protected_60m",
  ]);
  const successes = WINDOW_KEYS.map((window) =>
    sourceCount(exact[`successes_${window}`])
  );
  const protectedDenials = WINDOW_KEYS.map((window) =>
    sourceCount(exact[`protected_${window}`])
  );
  if (
    [...successes, ...protectedDenials].some(({ overflow }) => overflow)
  ) {
    return null;
  }
  const successValues = successes.map(({ value }) => value);
  const protectedValues = protectedDenials.map(({ value }) => value);
  if (
    !nestedCounts(successValues) ||
    !nestedCounts(protectedValues)
  ) {
    fail("source_invalid");
  }
  if (
    successValues.some((value, index) =>
      value + protectedValues[index] > MAX_EVIDENCE_COUNT
    )
  ) {
    return null;
  }
  return {
    "5m": {
      protectedDenials: protectedValues[0],
      successes: successValues[0],
    },
    "15m": {
      protectedDenials: protectedValues[1],
      successes: successValues[1],
    },
    "60m": {
      protectedDenials: protectedValues[2],
      successes: successValues[2],
    },
  };
}

function isAuditAlertRuleId(value: unknown): value is AuditAlertRuleId {
  return typeof value === "string" &&
    AUDIT_ALERT_RULE_IDS.some((ruleId) => ruleId === value);
}

function dimensionKindForRule(
  ruleId: AuditAlertRuleId,
): AuditAlertDimensionKind {
  if (
    ruleId === "pgid.admin.sensitive_activity.v1" ||
    ruleId === "pgid.admin.directory_volume.v1"
  ) {
    return "actor_hmac";
  }
  if (
    ruleId === "pgid.restricted.sensitive_denied.v1" ||
    ruleId === "pgid.recovery.passkey_failure.v1" ||
    ruleId === "pgid.passkey.step_up_failure.v1"
  ) {
    return "subject_hmac";
  }
  return "global";
}

function addIncomplete(
  incomplete: Map<string, IncompleteAuditAlertSource>,
  ruleId: AuditAlertRuleId,
  dimensionKind: AuditAlertDimensionKind,
): void {
  incomplete.set(`${ruleId}\0${dimensionKind}`, { dimensionKind, ruleId });
}

function hasIncomplete(
  incomplete: ReadonlyMap<string, IncompleteAuditAlertSource>,
  ruleId: AuditAlertRuleId,
  dimensionKind: AuditAlertDimensionKind,
): boolean {
  return incomplete.has(`${ruleId}\0${dimensionKind}`);
}

function asAuditObservation(value: unknown): AuditAlertObservation {
  let observation: AlertRuleObservation;
  try {
    observation = parseAlertObservation(value);
  } catch {
    fail("source_invalid");
  }
  switch (observation.ruleId) {
    case "pgid.registration.rate_limited.v1":
    case "pgid.registration.denied.v1":
    case "pgid.registration.challenge_unavailable.v1":
    case "pgid.registration.restricted_created.v1":
    case "pgid.restricted.sensitive_denied.v1":
    case "pgid.recovery.entry_abuse.v1":
    case "pgid.recovery.passkey_failure.v1":
    case "pgid.passkey.step_up_failure.v1":
    case "pgid.admin.sensitive_activity.v1":
    case "pgid.admin.directory_volume.v1":
      return observation;
    default:
      fail("source_invalid");
  }
}

function rawIdentity(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || value.length < 1 || value.length > 512) {
    fail("source_invalid");
  }
  return value;
}

function storedReference(
  reference: unknown,
  version: unknown,
): HashedAlertReference | null {
  if (reference === null && version === null) return null;
  const candidate = { keyVersion: version, value: reference };
  if (!isHashedAlertReference(candidate)) fail("source_invalid");
  return candidate;
}

async function resolveActorReference(
  key: string,
  row: UnknownRecord,
  rawByReference: Map<string, string>,
): Promise<HashedAlertReference | null> {
  const raw = rawIdentity(row.actor_user_id);
  const stored = storedReference(
    row.actor_ref,
    row.actor_ref_hash_version,
  );
  if (raw === null) return stored;
  const derived = await deriveAlertReferenceV1(key, "actor_hmac", raw);
  const existingRaw = rawByReference.get(derived.value);
  if (existingRaw !== undefined && existingRaw !== raw) fail("source_invalid");
  rawByReference.set(derived.value, raw);
  if (stored !== null && stored.value !== derived.value) fail("source_invalid");
  return stored ?? derived;
}

async function resolveSubjectReference(
  key: string,
  value: unknown,
  rawByReference: Map<string, string>,
): Promise<HashedAlertReference | null> {
  const raw = rawIdentity(value);
  if (raw === null) return null;
  const derived = await deriveAlertReferenceV1(key, "subject_hmac", raw);
  const existingRaw = rawByReference.get(derived.value);
  if (existingRaw !== undefined && existingRaw !== raw) fail("source_invalid");
  rawByReference.set(derived.value, raw);
  return derived;
}

function addCountWindows(
  target: CountWindows | undefined,
  source: CountWindows,
): CountWindows | null {
  if (!target) return source;
  const values = WINDOW_KEYS.map((window) => target[window] + source[window]);
  if (values.some((value) => value > MAX_EVIDENCE_COUNT)) return null;
  return { "5m": values[0], "15m": values[1], "60m": values[2] };
}

function addAdminWindows(
  target: AdminSensitiveWindows | undefined,
  source: AdminSensitiveWindows,
): AdminSensitiveWindows | null {
  if (!target) return source;
  const merged = {} as Record<AlertWindowKey, {
    protectedDenials: number;
    successes: number;
  }>;
  for (const window of WINDOW_KEYS) {
    const protectedDenials = target[window].protectedDenials +
      source[window].protectedDenials;
    const successes = target[window].successes + source[window].successes;
    if (
      protectedDenials > MAX_EVIDENCE_COUNT ||
      successes > MAX_EVIDENCE_COUNT ||
      protectedDenials + successes > MAX_EVIDENCE_COUNT
    ) {
      return null;
    }
    merged[window] = { protectedDenials, successes };
  }
  return merged;
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
  let expected: HashedAlertReference;
  try {
    expected = await deriveAlertHashKeyFingerprintV1(key);
  } catch {
    return false;
  }
  return expected.value === row.fingerprint_ref;
}

function windowBindings(
  windows: ReturnType<typeof alertWindowsAt>,
): readonly [string, string, string, string] {
  return [
    windows[0].startInclusive,
    windows[1].startInclusive,
    windows[2].startInclusive,
    windows[0].endExclusive,
  ];
}

function ratioBindings(
  windows: ReturnType<typeof alertWindowsAt>,
): readonly [string, string, string, string, string, string] {
  return [
    windows[0].startInclusive,
    windows[0].startInclusive,
    windows[1].startInclusive,
    windows[1].startInclusive,
    windows[2].startInclusive,
    windows[0].endExclusive,
  ];
}

function recoveryEntryBindings(
  windows: ReturnType<typeof alertWindowsAt>,
): readonly [string, string, string, string, string, string, string, string] {
  return [
    windows[0].startInclusive,
    windows[0].startInclusive,
    windows[0].startInclusive,
    windows[1].startInclusive,
    windows[1].startInclusive,
    windows[1].startInclusive,
    windows[2].startInclusive,
    windows[0].endExclusive,
  ];
}

function restrictedBindings(
  windows: ReturnType<typeof alertWindowsAt>,
): readonly [string, string, string, string, string, string] {
  return [
    windows[0].startInclusive,
    windows[0].startInclusive,
    windows[1].startInclusive,
    windows[1].startInclusive,
    windows[2].startInclusive,
    windows[0].endExclusive,
  ];
}

function adminSensitiveBindings(
  windows: ReturnType<typeof alertWindowsAt>,
): readonly [string, string, string, string, string, string] {
  return [
    windows[0].startInclusive,
    windows[0].startInclusive,
    windows[1].startInclusive,
    windows[1].startInclusive,
    windows[2].startInclusive,
    windows[0].endExclusive,
  ];
}

function sortObservations(
  observations: readonly AuditAlertObservation[],
): readonly AuditAlertObservation[] {
  const order = new Map<string, number>(
    AUDIT_ALERT_RULE_IDS.map((ruleId, index) => [ruleId, index]),
  );
  return [...observations].sort((left, right) => {
    const byRule = (order.get(left.ruleId) ?? -1) -
      (order.get(right.ruleId) ?? -1);
    if (byRule !== 0) return byRule;
    const leftReference = "reference" in left.dimension
      ? left.dimension.reference.value
      : "";
    const rightReference = "reference" in right.dimension
      ? right.dimension.reference.value
      : "";
    return leftReference < rightReference
      ? -1
      : leftReference > rightReference ? 1 : 0;
  });
}

export async function readAuditAlertSources(
  database: D1Database,
  inputValue: ReadAuditAlertSourcesInput,
): Promise<AuditAlertSourceResult> {
  if (arguments.length !== 2) {
    throw new AlertAuditSourceRepositoryError("invalid_input");
  }
  let input: ReadAuditAlertSourcesInput;
  try {
    input = parseInput(inputValue);
  } catch (error) {
    throw redactedRepositoryError(error, "invalid_input");
  }
  const windows = alertWindowsAt(input.asOf);
  const basicBindings = windowBindings(windows);
  const ratioWindowBindings = ratioBindings(windows);
  let results: D1Result<Record<string, unknown>>[];
  try {
    results = await database.batch<Record<string, unknown>>([
      database.prepare(ALERT_AUDIT_TIMESTAMP_INTEGRITY_QUERY),
      database.prepare(SENTINEL_QUERY),
      database.prepare(ALERT_AUDIT_TRACKED_DIMENSIONS_QUERY).bind(
        input.environment,
      ),
      database.prepare(REGISTRATION_RATE_LIMITED_QUERY).bind(...basicBindings),
      database.prepare(REGISTRATION_DENIED_QUERY).bind(...basicBindings),
      database.prepare(REGISTRATION_CHALLENGE_QUERY).bind(...ratioWindowBindings),
      database.prepare(REGISTRATION_RESTRICTED_CREATED_QUERY).bind(
        ...basicBindings,
      ),
      database.prepare(RESTRICTED_DENIAL_QUERY).bind(
        ...restrictedBindings(windows),
      ),
      database.prepare(RECOVERY_ENTRY_QUERY).bind(
        ...recoveryEntryBindings(windows),
      ),
      database.prepare(RECOVERY_PASSKEY_GLOBAL_QUERY).bind(
        ...ratioWindowBindings,
      ),
      database.prepare(RECOVERY_PASSKEY_DIMENSION_QUERY).bind(
        ...ratioWindowBindings,
      ),
      database.prepare(PASSKEY_STEP_UP_GLOBAL_QUERY).bind(
        ...ratioWindowBindings,
      ),
      database.prepare(PASSKEY_STEP_UP_DIMENSION_QUERY).bind(
        ...ratioWindowBindings,
      ),
      database.prepare(ADMIN_SENSITIVE_QUERY).bind(
        ...adminSensitiveBindings(windows),
      ),
      database.prepare(ADMIN_DIRECTORY_QUERY).bind(...basicBindings),
    ]);
  } catch {
    throw new AlertAuditSourceRepositoryError("source_unavailable");
  }

  try {
    if (results.length !== Object.keys(RESULT_INDEX).length) {
      fail("source_invalid");
    }
    assertCanonicalTimestampSource(results, RESULT_INDEX.timestampIntegrity);
    const incomplete = new Map<string, IncompleteAuditAlertSource>();
    const observations: AuditAlertObservation[] = [];
    const keyAvailable = await sentinelKeyAvailable(
      resultRows(results, RESULT_INDEX.sentinel),
      input.hmacKeyBase64Url,
    );
    if (!keyAvailable) {
      for (const [ruleId, dimensionKind] of HASHED_SOURCE_IDENTITIES) {
        addIncomplete(incomplete, ruleId, dimensionKind);
      }
    }

    const addGlobalCount = (ruleId: AuditAlertRuleId, index: number): void => {
      const parsed = parseCountWindows(oneRow(results, index, [
        "count_5m",
        "count_15m",
        "count_60m",
      ]));
      if (parsed === null) {
        addIncomplete(incomplete, ruleId, "global");
        return;
      }
      observations.push(asAuditObservation({
        asOf: input.asOf,
        dimension: { kind: "global" },
        ruleId,
        windows: {
          "5m": { count: parsed["5m"] },
          "15m": { count: parsed["15m"] },
          "60m": { count: parsed["60m"] },
        },
      }));
    };

    addGlobalCount(
      "pgid.registration.rate_limited.v1",
      RESULT_INDEX.registrationRateLimited,
    );
    addGlobalCount(
      "pgid.registration.denied.v1",
      RESULT_INDEX.registrationDenied,
    );
    addGlobalCount(
      "pgid.registration.restricted_created.v1",
      RESULT_INDEX.registrationRestrictedCreated,
    );

    const challenge = parseRatioWindows(oneRow(
      results,
      RESULT_INDEX.registrationChallenge,
      RATIO_KEYS,
    ));
    if (challenge === null) {
      addIncomplete(
        incomplete,
        "pgid.registration.challenge_unavailable.v1",
        "global",
      );
    } else {
      observations.push(asAuditObservation({
        asOf: input.asOf,
        dimension: { kind: "global" },
        ruleId: "pgid.registration.challenge_unavailable.v1",
        windows: challenge,
      }));
    }

    const recoveryEntry = parseRecoveryEntryWindows(oneRow(
      results,
      RESULT_INDEX.recoveryEntry,
      WINDOW_KEYS.flatMap((window) => [
        `denied_${window}`,
        `rate_limited_${window}`,
        `started_${window}`,
      ]),
    ));
    if (recoveryEntry === null) {
      addIncomplete(incomplete, "pgid.recovery.entry_abuse.v1", "global");
    } else {
      observations.push(asAuditObservation({
        asOf: input.asOf,
        dimension: { kind: "global" },
        ruleId: "pgid.recovery.entry_abuse.v1",
        windows: recoveryEntry,
      }));
    }

    const addGlobalRatio = (
      ruleId:
        | "pgid.recovery.passkey_failure.v1"
        | "pgid.passkey.step_up_failure.v1",
      index: number,
    ): void => {
      const parsed = parseRatioWindows(oneRow(results, index, RATIO_KEYS));
      if (parsed === null) {
        addIncomplete(incomplete, ruleId, "global");
        return;
      }
      observations.push(asAuditObservation({
        asOf: input.asOf,
        dimension: { kind: "global" },
        ruleId,
        windows: parsed,
      }));
    };
    addGlobalRatio(
      "pgid.recovery.passkey_failure.v1",
      RESULT_INDEX.recoveryPasskeyGlobal,
    );
    addGlobalRatio(
      "pgid.passkey.step_up_failure.v1",
      RESULT_INDEX.passkeyStepUpGlobal,
    );

    const trackedByRule = new Map<AuditAlertRuleId, Set<string>>();
    const trackedCountByRule = new Map<AuditAlertRuleId, number>();
    const trackedRows = resultRows(results, RESULT_INDEX.tracked);
    for (const rowValue of trackedRows) {
      const row = exactRecord(rowValue, [
        "rule_id",
        "subject_ref",
        "hash_version",
      ]);
      if (!isAuditAlertRuleId(row.rule_id)) fail("source_invalid");
      const dimensionKind = dimensionKindForRule(row.rule_id);
      if (dimensionKind === "global") fail("source_invalid");
      const reference = storedReference(row.subject_ref, row.hash_version);
      if (reference === null) fail("source_invalid");
      const sourcePosition = (trackedCountByRule.get(row.rule_id) ?? 0) + 1;
      trackedCountByRule.set(row.rule_id, sourcePosition);
      if (sourcePosition > MAX_DIMENSION_GROUPS) {
        addIncomplete(incomplete, row.rule_id, dimensionKind);
        continue;
      }
      const refs = trackedByRule.get(row.rule_id) ?? new Set<string>();
      refs.add(reference.value);
      trackedByRule.set(row.rule_id, refs);
    }

    if (keyAvailable && input.hmacKeyBase64Url !== null) {
      const hmacKeyBase64Url = input.hmacKeyBase64Url;
      const subjectRawByReference = new Map<string, string>();
      const actorRawByReference = new Map<string, string>();

      const restrictedRule = "pgid.restricted.sensitive_denied.v1" as const;
      const restrictedMetrics = new Map<string, RestrictedWindows>();
      const restrictedRows = resultRows(results, RESULT_INDEX.restrictedDenial);
      if (restrictedRows.length > MAX_DIMENSION_GROUPS) {
        addIncomplete(incomplete, restrictedRule, "subject_hmac");
      } else {
        for (const row of restrictedRows) {
          const parsed = parseRestrictedWindows(row);
          if (parsed === null) {
            addIncomplete(incomplete, restrictedRule, "subject_hmac");
            break;
          }
          const reference = await resolveSubjectReference(
            hmacKeyBase64Url,
            row.raw_identity,
            subjectRawByReference,
          );
          if (reference === null) {
            addIncomplete(incomplete, restrictedRule, "subject_hmac");
            break;
          }
          restrictedMetrics.set(reference.value, parsed);
        }
      }
      if (!hasIncomplete(incomplete, restrictedRule, "subject_hmac")) {
        for (const reference of trackedByRule.get(restrictedRule) ?? []) {
          if (!restrictedMetrics.has(reference)) {
            restrictedMetrics.set(reference, {
              "5m": { count: 0, knownSurfaces: 0 },
              "15m": { count: 0, knownSurfaces: 0 },
              "60m": { count: 0, knownSurfaces: 0 },
            });
          }
        }
        if (restrictedMetrics.size > MAX_DIMENSION_GROUPS) {
          addIncomplete(incomplete, restrictedRule, "subject_hmac");
        }
      }
      if (!hasIncomplete(incomplete, restrictedRule, "subject_hmac")) {
        for (const [value, metrics] of restrictedMetrics) {
          observations.push(asAuditObservation({
            asOf: input.asOf,
            dimension: {
              kind: "subject_hmac",
              reference: { keyVersion: 1, value },
            },
            ruleId: restrictedRule,
            windows: metrics,
          }));
        }
      }

      const addSubjectRatioRows = async (
        ruleId:
          | "pgid.recovery.passkey_failure.v1"
          | "pgid.passkey.step_up_failure.v1",
        index: number,
      ): Promise<void> => {
        const metricsByReference = new Map<string, RatioWindows>();
        const rows = resultRows(results, index);
        if (rows.length > MAX_DIMENSION_GROUPS) {
          addIncomplete(incomplete, ruleId, "subject_hmac");
          return;
        }
        for (const rowValue of rows) {
          const row = exactRecord(rowValue, ["raw_identity", ...RATIO_KEYS]);
          const metrics = parseRatioWindows({
            numerator_5m: row.numerator_5m,
            denominator_5m: row.denominator_5m,
            numerator_15m: row.numerator_15m,
            denominator_15m: row.denominator_15m,
            numerator_60m: row.numerator_60m,
            denominator_60m: row.denominator_60m,
          });
          if (metrics === null) {
            addIncomplete(incomplete, ruleId, "subject_hmac");
            return;
          }
          const reference = await resolveSubjectReference(
            hmacKeyBase64Url,
            row.raw_identity,
            subjectRawByReference,
          );
          if (reference === null) {
            addIncomplete(incomplete, ruleId, "subject_hmac");
            return;
          }
          metricsByReference.set(reference.value, metrics);
        }
        for (const reference of trackedByRule.get(ruleId) ?? []) {
          if (!metricsByReference.has(reference)) {
            metricsByReference.set(reference, {
              "5m": { denominator: 0, numerator: 0 },
              "15m": { denominator: 0, numerator: 0 },
              "60m": { denominator: 0, numerator: 0 },
            });
          }
        }
        if (metricsByReference.size > MAX_DIMENSION_GROUPS) {
          addIncomplete(incomplete, ruleId, "subject_hmac");
          return;
        }
        for (const [value, metrics] of metricsByReference) {
          observations.push(asAuditObservation({
            asOf: input.asOf,
            dimension: {
              kind: "subject_hmac",
              reference: { keyVersion: 1, value },
            },
            ruleId,
            windows: metrics,
          }));
        }
      };
      await addSubjectRatioRows(
        "pgid.recovery.passkey_failure.v1",
        RESULT_INDEX.recoveryPasskeyDimension,
      );
      await addSubjectRatioRows(
        "pgid.passkey.step_up_failure.v1",
        RESULT_INDEX.passkeyStepUpDimension,
      );

      const adminSensitiveRule = "pgid.admin.sensitive_activity.v1" as const;
      const adminSensitiveMetrics = new Map<string, AdminSensitiveWindows>();
      const adminSensitiveRows = resultRows(
        results,
        RESULT_INDEX.adminSensitive,
      );
      if (adminSensitiveRows.length > MAX_DIMENSION_GROUPS) {
        addIncomplete(incomplete, adminSensitiveRule, "actor_hmac");
      } else {
        for (const rowValue of adminSensitiveRows) {
          const row = exactRecord(rowValue, [
            "actor_user_id",
            "actor_ref",
            "actor_ref_hash_version",
            "successes_5m",
            "protected_5m",
            "successes_15m",
            "protected_15m",
            "successes_60m",
            "protected_60m",
          ]);
          const metrics = parseAdminSensitiveWindows(row);
          if (metrics === null) {
            addIncomplete(incomplete, adminSensitiveRule, "actor_hmac");
            break;
          }
          const reference = await resolveActorReference(
            hmacKeyBase64Url,
            row,
            actorRawByReference,
          );
          if (reference === null) {
            addIncomplete(incomplete, adminSensitiveRule, "actor_hmac");
            break;
          }
          const merged = addAdminWindows(
            adminSensitiveMetrics.get(reference.value),
            metrics,
          );
          if (merged === null) {
            addIncomplete(incomplete, adminSensitiveRule, "actor_hmac");
            break;
          }
          adminSensitiveMetrics.set(reference.value, merged);
        }
      }
      if (!hasIncomplete(incomplete, adminSensitiveRule, "actor_hmac")) {
        for (const reference of trackedByRule.get(adminSensitiveRule) ?? []) {
          if (!adminSensitiveMetrics.has(reference)) {
            adminSensitiveMetrics.set(reference, {
              "5m": { protectedDenials: 0, successes: 0 },
              "15m": { protectedDenials: 0, successes: 0 },
              "60m": { protectedDenials: 0, successes: 0 },
            });
          }
        }
        if (adminSensitiveMetrics.size > MAX_DIMENSION_GROUPS) {
          addIncomplete(incomplete, adminSensitiveRule, "actor_hmac");
        }
      }
      if (!hasIncomplete(incomplete, adminSensitiveRule, "actor_hmac")) {
        for (const [value, metrics] of adminSensitiveMetrics) {
          observations.push(asAuditObservation({
            asOf: input.asOf,
            dimension: {
              kind: "actor_hmac",
              reference: { keyVersion: 1, value },
            },
            ruleId: adminSensitiveRule,
            windows: metrics,
          }));
        }
      }

      const adminDirectoryRule = "pgid.admin.directory_volume.v1" as const;
      const directoryMetrics = new Map<string, CountWindows>();
      const directoryRows = resultRows(results, RESULT_INDEX.adminDirectory);
      if (directoryRows.length > MAX_DIMENSION_GROUPS) {
        addIncomplete(incomplete, adminDirectoryRule, "actor_hmac");
      } else {
        for (const rowValue of directoryRows) {
          const row = exactRecord(rowValue, [
            "actor_user_id",
            "actor_ref",
            "actor_ref_hash_version",
            "count_5m",
            "count_15m",
            "count_60m",
          ]);
          const metrics = parseCountWindows({
            count_5m: row.count_5m,
            count_15m: row.count_15m,
            count_60m: row.count_60m,
          });
          if (metrics === null) {
            addIncomplete(incomplete, adminDirectoryRule, "actor_hmac");
            break;
          }
          const reference = await resolveActorReference(
            hmacKeyBase64Url,
            row,
            actorRawByReference,
          );
          if (reference === null) {
            addIncomplete(incomplete, adminDirectoryRule, "actor_hmac");
            break;
          }
          const merged = addCountWindows(
            directoryMetrics.get(reference.value),
            metrics,
          );
          if (merged === null) {
            addIncomplete(incomplete, adminDirectoryRule, "actor_hmac");
            break;
          }
          directoryMetrics.set(reference.value, merged);
        }
      }
      if (!hasIncomplete(incomplete, adminDirectoryRule, "actor_hmac")) {
        for (const reference of trackedByRule.get(adminDirectoryRule) ?? []) {
          if (!directoryMetrics.has(reference)) {
            directoryMetrics.set(reference, {
              "5m": 0,
              "15m": 0,
              "60m": 0,
            });
          }
        }
        if (directoryMetrics.size > MAX_DIMENSION_GROUPS) {
          addIncomplete(incomplete, adminDirectoryRule, "actor_hmac");
        }
      }
      if (!hasIncomplete(incomplete, adminDirectoryRule, "actor_hmac")) {
        for (const [value, metrics] of directoryMetrics) {
          observations.push(asAuditObservation({
            asOf: input.asOf,
            dimension: {
              kind: "actor_hmac",
              reference: { keyVersion: 1, value },
            },
            ruleId: adminDirectoryRule,
            windows: {
              "5m": { count: metrics["5m"] },
              "15m": { count: metrics["15m"] },
              "60m": { count: metrics["60m"] },
            },
          }));
        }
      }
    }

    const completeObservations = observations.filter((observation) =>
      !hasIncomplete(
        incomplete,
        observation.ruleId,
        observation.dimension.kind === "global"
          ? "global"
          : observation.dimension.kind,
      )
    );
    const incompleteSources = [...incomplete.values()].sort((left, right) => {
      const byRule = AUDIT_ALERT_RULE_IDS.indexOf(left.ruleId) -
        AUDIT_ALERT_RULE_IDS.indexOf(right.ruleId);
      return byRule !== 0
        ? byRule
        : left.dimensionKind < right.dimensionKind
        ? -1
        : left.dimensionKind > right.dimensionKind ? 1 : 0;
    });
    return {
      incomplete: incompleteSources,
      observations: sortObservations(completeObservations),
    };
  } catch (error) {
    throw redactedRepositoryError(error, "source_invalid");
  }
}
