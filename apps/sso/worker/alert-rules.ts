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
export type AlertSourceKind = "d1_exact" | "queue_approximate";
export type AlertWindowKey = "5m" | "15m" | "60m";
export type AlertResolutionMode = "automatic" | "manual";

export const ALERT_WINDOW_KEYS = ["5m", "15m", "60m"] as const;
export const ALERT_EVIDENCE_WINDOW_ORDER = ALERT_WINDOW_KEYS;

export const ALERT_WINDOW_SECONDS: Readonly<Record<AlertWindowKey, number>> = {
  "5m": 300,
  "15m": 900,
  "60m": 3_600,
};

const MAX_EVIDENCE_VALUE = 1_000_000_000;
const MAX_RATIO_FIELD = 1_000_000;
const MAX_QUEUE_BACKLOG_BYTES = 1_000_000_000_000;
export const ALERT_RUNTIME_GENERATION_MAX = Number.MAX_SAFE_INTEGER;
export const ALERT_RUNTIME_REVISION_MAX = Number.MAX_SAFE_INTEGER;
const HMAC_REFERENCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const RULE_ID_SET = new Set<string>(ALERT_RULE_IDS);

export const ALERT_RUNTIME_SOURCE_QUERY = `SELECT
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

export const ALERT_QUEUE_NAMES = [
  "security_events_dlq",
  "logout_deliveries_dlq",
  "alert_deliveries_dlq",
  "audit_archive_dlq",
] as const;
export type AlertQueueName = (typeof ALERT_QUEUE_NAMES)[number];
export type AlertQueueRuntimeComponent =
  | "security_dlq"
  | "logout_dlq"
  | "alert_dlq"
  | "audit_archive_dlq";
export const ALERT_QUEUE_COMPONENTS = {
  alert_deliveries_dlq: "alert_dlq",
  audit_archive_dlq: "audit_archive_dlq",
  logout_deliveries_dlq: "logout_dlq",
  security_events_dlq: "security_dlq",
} as const satisfies Readonly<
  Record<AlertQueueName, AlertQueueRuntimeComponent>
>;
const ALERT_QUEUE_NAME_SET = new Set<string>(ALERT_QUEUE_NAMES);

export const ALERT_HASHED_DIMENSION_KINDS = [
  "subject_hmac",
  "actor_hmac",
  "client_hmac",
] as const;
export type AlertHashedDimensionKind =
  (typeof ALERT_HASHED_DIMENSION_KINDS)[number];
export const ALERT_HMAC_REFERENCE_DOMAINS = [
  ...ALERT_HASHED_DIMENSION_KINDS,
  "reporter_hmac",
] as const;
export type AlertHmacReferenceDomain =
  (typeof ALERT_HMAC_REFERENCE_DOMAINS)[number];
const HASHED_DIMENSION_KIND_SET = new Set<string>(
  ALERT_HASHED_DIMENSION_KINDS,
);
const HMAC_REFERENCE_DOMAIN_SET = new Set<string>(ALERT_HMAC_REFERENCE_DOMAINS);

export interface HashedAlertReference {
  keyVersion: 1;
  value: string;
}

export type AlertDimension =
  | { kind: "global" }
  | { kind: "subject_hmac"; reference: HashedAlertReference }
  | { kind: "actor_hmac"; reference: HashedAlertReference }
  | { kind: "client_hmac"; reference: HashedAlertReference }
  | { kind: "queue"; queue: AlertQueueName };

export type HashedAlertDimension = Extract<
  AlertDimension,
  { reference: HashedAlertReference }
>;

export interface AlertWindowDescriptor {
  endExclusive: string;
  key: AlertWindowKey;
  minutes: number;
  startInclusive: string;
}

function canonicalTimestamp(value: unknown, name: string): string {
  if (typeof value !== "string") {
    throw new Error(`${name} must be a canonical UTC ISO timestamp`);
  }
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error(`${name} must be a canonical UTC ISO timestamp`);
  }
  return value;
}

export function alertWindowsAt(asOf: string): readonly AlertWindowDescriptor[] {
  const canonical = canonicalTimestamp(asOf, "asOf");
  const timestamp = new Date(canonical).getTime();
  return ALERT_WINDOW_KEYS.map((key) => ({
    endExclusive: canonical,
    key,
    minutes: ALERT_WINDOW_SECONDS[key] / 60,
    startInclusive: new Date(
      timestamp - ALERT_WINDOW_SECONDS[key] * 1_000,
    ).toISOString(),
  }));
}

type UnknownRecord = Record<string, unknown>;

function recordValue(value: unknown, name: string): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as UnknownRecord;
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  name: string,
): UnknownRecord {
  const record = recordValue(value, name);
  const actual = Object.keys(record);
  if (
    actual.length !== keys.length ||
    keys.some((key) => !Object.hasOwn(record, key))
  ) {
    throw new Error(`${name} must contain only the canonical keys`);
  }
  return record;
}

export interface AlertRuntimeThresholdInput {
  evaluatorAgeSeconds: number | null;
}

const ALERT_RUNTIME_STATUSES = new Set([
  "disabled",
  "healthy",
  "degraded",
  "failing",
  "unavailable",
]);
const ALERT_RUNTIME_ERROR_CODES = new Set([
  "metrics_unavailable",
  "evaluator_failed",
  "delivery_failed",
  "fanout_failed",
  "logout_failed",
  "source_incomplete",
  "unknown",
]);
const ALERT_RUNTIME_SOURCE_PROJECTION_KEYS = [
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
] as const;

function runtimeSourceTimestamp(value: unknown, name: string): string | null {
  try {
    return canonicalTimestamp(value, name);
  } catch {
    return null;
  }
}

function runtimeSourceInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): number | null {
  return Number.isSafeInteger(value) &&
      (value as number) >= minimum &&
      (value as number) <= maximum
    ? value as number
    : null;
}

// The repository query and schema guards establish D1 provenance. This parser
// only validates the exact projection shape and its bounded chronology.
export function parseAlertRuntimeSourceCompleteness(
  value: unknown,
  asOf: string,
): AlertRuntimeThresholdInput | null {
  if (arguments.length !== 2) {
    throw new Error("alert runtime source parser accepts only projection and asOf");
  }
  const evaluationTime = new Date(canonicalTimestamp(asOf, "asOf")).getTime();
  const record = exactRecord(
    value,
    ALERT_RUNTIME_SOURCE_PROJECTION_KEYS,
    "alert runtime source projection",
  );
  const sentinelValues = [
    record.bootstrap_component,
    record.first_success_at,
    record.source_generation,
    record.source_revision,
  ];
  if (sentinelValues.every((entry) => entry === null)) return null;

  const missing = (): AlertRuntimeThresholdInput => ({ evaluatorAgeSeconds: null });
  const firstSuccessAt = runtimeSourceTimestamp(
    record.first_success_at,
    "bootstrap first_success_at",
  );
  const sourceGeneration = runtimeSourceInteger(
    record.source_generation,
    1,
    ALERT_RUNTIME_GENERATION_MAX,
  );
  const sourceRevision = runtimeSourceInteger(
    record.source_revision,
    1,
    ALERT_RUNTIME_REVISION_MAX,
  );
  if (
    record.bootstrap_component !== "evaluator" ||
    firstSuccessAt === null ||
    new Date(firstSuccessAt).getTime() > evaluationTime ||
    sourceGeneration === null ||
    sourceRevision === null
  ) {
    return missing();
  }

  const runtimeGeneration = runtimeSourceInteger(
    record.runtime_generation,
    0,
    ALERT_RUNTIME_GENERATION_MAX,
  );
  const runtimeRevision = runtimeSourceInteger(
    record.runtime_revision,
    0,
    ALERT_RUNTIME_REVISION_MAX,
  );
  const lastStartedAt = runtimeSourceTimestamp(
    record.runtime_last_started_at,
    "runtime last_started_at",
  );
  const lastSuccessAt = runtimeSourceTimestamp(
    record.runtime_last_success_at,
    "runtime last_success_at",
  );
  const updatedAt = runtimeSourceTimestamp(
    record.runtime_updated_at,
    "runtime updated_at",
  );
  if (
    record.runtime_component !== "evaluator" ||
    typeof record.runtime_status !== "string" ||
    !ALERT_RUNTIME_STATUSES.has(record.runtime_status) ||
    runtimeGeneration === null ||
    runtimeGeneration < sourceGeneration ||
    runtimeRevision === null ||
    runtimeRevision < sourceRevision ||
    lastStartedAt === null ||
    lastSuccessAt === null ||
    updatedAt === null
  ) {
    return missing();
  }

  const firstSuccessTime = new Date(firstSuccessAt).getTime();
  const lastStartedTime = new Date(lastStartedAt).getTime();
  const lastSuccessTime = new Date(lastSuccessAt).getTime();
  const updatedTime = new Date(updatedAt).getTime();
  if (
    firstSuccessTime > updatedTime ||
    lastStartedTime > updatedTime ||
    lastSuccessTime < firstSuccessTime ||
    lastSuccessTime > updatedTime ||
    updatedTime > evaluationTime
  ) {
    return missing();
  }

  const hasErrorAt = record.runtime_last_error_at !== null;
  const hasErrorCode = record.runtime_last_error_code !== null;
  if (hasErrorAt !== hasErrorCode) return missing();
  if (hasErrorAt) {
    const lastErrorAt = runtimeSourceTimestamp(
      record.runtime_last_error_at,
      "runtime last_error_at",
    );
    if (
      lastErrorAt === null ||
      typeof record.runtime_last_error_code !== "string" ||
      !ALERT_RUNTIME_ERROR_CODES.has(record.runtime_last_error_code) ||
      new Date(lastErrorAt).getTime() > updatedTime
    ) {
      return missing();
    }
  }

  const evaluatorAgeSeconds = Math.floor(
    (evaluationTime - lastSuccessTime) / 1_000,
  );
  return evaluatorAgeSeconds <= MAX_EVIDENCE_VALUE
    ? { evaluatorAgeSeconds }
    : missing();
}

export function isHashedAlertReference(
  value: unknown,
): value is HashedAlertReference {
  try {
    parseHashedReference(value);
    return true;
  } catch {
    return false;
  }
}

function parseHashedReference(value: unknown): HashedAlertReference {
  const record = exactRecord(value, ["keyVersion", "value"], "alert reference");
  if (record.keyVersion !== 1) {
    throw new Error("alert reference key version must be 1");
  }
  if (
    typeof record.value !== "string" ||
    !isCanonicalBase64Url32(record.value)
  ) {
    throw new Error("alert reference must be a canonical unpadded base64url HMAC");
  }
  return { keyVersion: 1, value: record.value };
}

function isCanonicalBase64Url32(value: string): boolean {
  if (!HMAC_REFERENCE_PATTERN.test(value)) return false;
  const finalIndex = base64UrlIndex(value.at(-1) ?? "");
  return finalIndex >= 0 && finalIndex % 4 === 0;
}

function base64UrlIndex(character: string): number {
  if (character.length !== 1) return -1;
  const code = character.charCodeAt(0);
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 97 + 26;
  if (code >= 48 && code <= 57) return code - 48 + 52;
  if (character === "-") return 62;
  if (character === "_") return 63;
  return -1;
}

function decodeHmacKey(value: string): Uint8Array<ArrayBuffer> {
  if (!HMAC_REFERENCE_PATTERN.test(value)) {
    throw new Error("alert HMAC key must be 32-byte unpadded base64url");
  }
  let bytes: Uint8Array<ArrayBuffer> | undefined;
  try {
    const decoded = atob(`${value.replaceAll("-", "+").replaceAll("_", "/") }=`);
    if (decoded.length !== 32) throw new Error("invalid length");
    bytes = new Uint8Array(decoded.length);
    for (let index = 0; index < decoded.length; index += 1) {
      bytes[index] = decoded.charCodeAt(index);
    }
    if (base64Url(bytes) !== value) throw new Error("noncanonical encoding");
    const result = bytes;
    bytes = undefined;
    return result;
  } catch {
    throw new Error("alert HMAC key must be 32-byte unpadded base64url");
  } finally {
    bytes?.fill(0);
  }
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export async function deriveAlertReferenceV1(
  keyBase64Url: string,
  kind: AlertHmacReferenceDomain,
  raw: string,
): Promise<HashedAlertReference> {
  if (!HMAC_REFERENCE_DOMAIN_SET.has(kind)) {
    throw new Error("alert HMAC kind is not supported");
  }
  if (typeof raw !== "string" || raw.length < 1 || raw.length > 512) {
    throw new Error("alert HMAC input must contain 1 to 512 characters");
  }
  const keyBytes = decodeHmacKey(keyBase64Url);
  let signInput: Uint8Array<ArrayBuffer> | undefined;
  try {
    signInput = new TextEncoder().encode(`pgid-alert-v1\0${kind}\0${raw}`);
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { hash: "SHA-256", name: "HMAC" },
      false,
      ["sign"],
    );
    const signature = await crypto.subtle.sign(
      "HMAC",
      key,
      signInput,
    );
    return {
      keyVersion: 1,
      value: base64Url(new Uint8Array(signature)),
    };
  } finally {
    keyBytes.fill(0);
    signInput?.fill(0);
  }
}

export const RESTRICTED_ALERT_SURFACES = [
  "provider_link",
  "clients.manage",
  "clients.manage_all",
  "users.read",
  "users.invite",
  "users.manage",
  "users.assign_roles",
] as const;

export const OAUTH_REPORT_REASONS = [
  "impersonation",
  "phishing",
  "scope_abuse",
  "other",
] as const;

export const HIGH_RISK_OAUTH_REPORT_REASONS = [
  "impersonation",
  "phishing",
] as const;

export const HIGH_RISK_ADMIN_SUCCESS_EVENTS = [
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
] as const;

export const BOOTADMIN_PROTECTED_EVENTS = [
  "user.access_promoted",
  "user.access_restricted",
  "user.deleted",
  "user.reactivated",
  "user.role_changed",
  "user.sessions_revoked",
  "user.suspended",
] as const;

type AuditOutcome = "success" | "denied" | "failure";
type AuditMetricRole =
  | "count"
  | "denominator"
  | "known_surfaces"
  | "numerator"
  | "protected_denials"
  | "rate_limited"
  | "successes";

export interface AuditEventSourceFilter {
  eventTypes: readonly string[];
  metadata?: Readonly<{ key: string; values: readonly string[] }>;
  metricRoles: readonly AuditMetricRole[];
  outcome: AuditOutcome;
}

const AUDIT_EVENT_SOURCE_COLUMNS = {
  eventIdColumn: "id",
  eventTypeColumn: "event_type",
  metadataColumn: "metadata_json",
  occurredAtColumn: "occurred_at",
  outcomeColumn: "outcome",
} as const;

export type AlertSourceDescriptor =
  | Readonly<{
      eventIdColumn: "id";
      eventTypeColumn: "event_type";
      filters: readonly AuditEventSourceFilter[];
      includeGlobal: boolean;
      metadataColumn: "metadata_json";
      mode: "audit_event";
      occurredAtColumn: "occurred_at";
      outcomeColumn: "outcome";
      table: "audit_event";
    } & (
      | {
          actorRefColumn: "actor_ref";
          actorRefHashVersionColumn: "actor_ref_hash_version";
          completenessPredicate: "actor_user_id_or_actor_ref_present";
          coverageLookbackSeconds: 3_600;
          dimensionColumn: "actor_user_id";
          missingActorIdentity: "source_incomplete";
        }
      | { dimensionColumn: "subject_id" | null }
    )>
  | Readonly<{
      allReasons: readonly string[];
      completenessPredicate: "reporter_user_id_or_reporter_ref_present";
      coverageLookbackSeconds: 3_600;
      createdAtColumn: "created_at";
      dimensionColumn: "client_id";
      hashVersion: 1;
      highRiskReasons: readonly string[];
      missingReporterIdentity: "null_distinct_reporters";
      mode: "oauth_client_report";
      reasonColumn: "reason";
      reporterRefColumn: "reporter_ref";
      reporterRefDomain: "reporter_hmac";
      reporterRefHashVersionColumn: "reporter_ref_hash_version";
      reporterUserIdColumn: "reporter_user_id";
      table: "oauth_client_report";
    }>
  | Readonly<{
      detectionOnly: true;
      dimension: "global";
      graceSeconds: 300;
      join: "left";
      lookbackSeconds: 3_600;
      markerEventIdColumn: "event_id";
      markerTable: "security_event_delivery";
      mode: "audit_fanout";
      sourceIdColumn: "id";
      sourceTable: "audit_event";
      sourceTimeColumn: "occurred_at";
    }>
  | Readonly<{
      currentSnapshot: Readonly<{
        clientIdColumn: "client_id";
        createdAtColumn: "created_at";
        deadStatus: "dead";
        oldestAgeSecondsSemantics: "as_of_minus_oldest_current_unresolved_created_at_floor_seconds";
        scope: "all_current_rows_at_as_of";
        statusColumn: "status";
        unresolvedStatuses: readonly ["pending", "processing", "retry", "dead"];
      }>;
      dimensions: readonly ["global", "client_id"];
      mode: "logout_delivery";
      windows: Readonly<{
        attemptCompletedAtColumn: "completed_at";
        attemptCohortScope: "completed_at_in_half_open_window";
        attemptDeliveryIdColumn: "delivery_id";
        attemptOutcomeColumn: "outcome";
        attemptTable: "logout_delivery_attempt";
        deliveryClientIdColumn: "client_id";
        deliveryCohortColumn: "created_at";
        deliveryCohortScope: "created_at_in_half_open_window";
        deliveryIdColumn: "id";
        deliveryStatusColumn: "status";
        deliveryTable: "logout_delivery";
        eligibleStatuses: readonly [
          "pending",
          "processing",
          "retry",
          "delivered",
          "dead",
        ];
        leaseExpiredOutcome: "lease_expired";
        unresolvedStatuses: readonly ["pending", "processing", "retry", "dead"];
      }>;
    }>
  | Readonly<{
      dimension: "global";
      evaluator: Readonly<{
        ageSecondsSemantics: "as_of_minus_last_success_at_floor_seconds";
        bootstrap: Readonly<{
          completenessLayer: "repository_source";
          completenessParser: "parseAlertRuntimeSourceCompleteness";
          enablement: "one_way_immutable_repository_sentinel";
          insertion: "same_atomic_d1_batch_repository_insert_select_after_controlled_success";
          parserAttestation: "shape_and_chronology_only";
          postBootstrapInvalidDisposition: "emit_missing_threshold_input";
          postBootstrapStatuses: readonly [
            "disabled",
            "healthy",
            "degraded",
            "failing",
            "unavailable",
          ];
          preBootstrapDisposition: "exclude_without_threshold_input";
          provenance: "schema_guards_and_repository_query";
          query: Readonly<{
            access: "repository_only";
            anchor: "SELECT 'evaluator' AS expected_component";
            bootstrapJoin: "LEFT JOIN alert_evaluator_bootstrap AS b ON b.component = e.expected_component";
            projection: Readonly<{
              bootstrapComponent: "b.component AS bootstrap_component";
              firstSuccessAt: "b.first_success_at AS first_success_at";
              runtimeComponent: "r.component AS runtime_component";
              runtimeGeneration: "r.generation AS runtime_generation";
              runtimeLastErrorAt: "r.last_error_at AS runtime_last_error_at";
              runtimeLastErrorCode: "r.last_error_code AS runtime_last_error_code";
              runtimeLastStartedAt: "r.last_started_at AS runtime_last_started_at";
              runtimeLastSuccessAt: "r.last_success_at AS runtime_last_success_at";
              runtimeRevision: "r.revision AS runtime_revision";
              runtimeStatus: "r.status AS runtime_status";
              runtimeUpdatedAt: "r.updated_at AS runtime_updated_at";
              sourceGeneration: "b.source_generation AS source_generation";
              sourceRevision: "b.source_revision AS source_revision";
            }>;
            repositoryQuery: typeof ALERT_RUNTIME_SOURCE_QUERY;
            runtimeJoin: "LEFT JOIN alert_runtime_status AS r ON r.component = e.expected_component";
          }>;
          sentinel: Readonly<{
            columns: Readonly<{
              component: "component";
              firstSuccessAt: "first_success_at";
              sourceGeneration: "source_generation";
              sourceRevision: "source_revision";
            }>;
            component: "evaluator";
            foreignKey: Readonly<{
              column: "component";
              onDelete: "restrict";
              referencedColumn: "component";
              referencedTable: "alert_runtime_status";
            }>;
            immutable: true;
            singleton: true;
            table: "alert_evaluator_bootstrap";
          }>;
          statusAlone: "never_sufficient";
        }>;
        component: "evaluator";
        componentColumn: "component";
        lastSuccessAtColumn: "last_success_at";
        nullAgeSemantics: "post_bootstrap_evaluator_missing_only";
        runtimeStatuses: readonly [
          "disabled",
          "healthy",
          "degraded",
          "failing",
          "unavailable",
        ];
        statusColumn: "status";
      }>;
      mode: "alert_runtime";
      outbox: Readonly<{
        currentDeadCountSemantics: "status_equals_dead_at_as_of";
        currentDeadStatus: "dead";
        dueAgeSecondsSemantics: "as_of_minus_oldest_due_or_expired_time_floor_seconds";
        dueAgeSecondsNullSemantics: "no_due_or_expired_work_at_as_of";
        dueStatuses: readonly ["pending", "retry"];
        dueTimeColumn: "next_attempt_at";
        expiredProcessingStatus: "processing";
        expiredProcessingTimeColumn: "lease_expires_at";
        statusColumn: "status";
        table: "alert_outbox";
      }>;
      runtimeTable: "alert_runtime_status";
      thresholdInput: Readonly<{
        bootstrapFields: "forbidden";
        evaluatorAgeSecondsNull: "post_bootstrap_missing_immediate";
        preBootstrap: "no_observation";
      }>;
    }>
  | Readonly<{
      backlogBytesBindingField: "backlogBytes";
      backlogBytesColumn: "backlog_bytes";
      backlogBytesMaximum: 1_000_000_000_000;
      backlogCountBindingField: "backlogCount";
      backlogCountColumn: "backlog_count";
      backlogCountMaximum: 1_000_000_000;
      componentColumn: "component";
      consecutiveNonzeroSamplesColumn: "consecutive_nonzero_samples";
      consecutiveNonzeroSamplesMaximum: 1_000_000;
      criticalDurationSeconds: 900;
      dimension: "queue_name";
      invalidBindingMetrics: "unknown";
      method: "metrics";
      metricSampledAtColumn: "metric_sampled_at";
      mode: "queue_metrics";
      nonzeroSinceAtColumn: "nonzero_since_at";
      numericValidation: "finite_safe_nonnegative_integer";
      oldestMessageAgeSecondsColumn: "oldest_message_age_seconds";
      oldestMessageAgeSecondsMaximum: 1_000_000_000;
      oldestMessageTimestampBindingField: "oldestMessageTimestamp";
      oldestMessageTimestampNormalization: "sampled_at_minus_oldest_message_timestamp_floor_seconds";
      queueComponentByName: typeof ALERT_QUEUE_COMPONENTS;
      queueNames: readonly AlertQueueName[];
      sampleCadenceSeconds: 60;
      streakStateTable: "alert_runtime_status";
    }>;

export type AlertMetricName =
  | "consecutive_nonzero_samples"
  | "count"
  | "dead"
  | "dead_outbox"
  | "depth"
  | "distinct_reporters"
  | "evaluator_age_seconds"
  | "evaluator_missing"
  | "high_risk_count"
  | "known_surfaces"
  | "lease_expired"
  | "missing"
  | "oldest_unresolved_age_seconds"
  | "outbox_due_age_seconds"
  | "protected_denials"
  | "rate_limited"
  | "ratio"
  | "successes";

type InternalMetricName =
  | "consecutiveNonzeroSamples"
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
  | "missingOlderThan15mCount"
  | "missingOlderThan5mCount"
  | "numerator"
  | "oldestUnresolvedAgeSeconds"
  | "outboxDueAgeSeconds"
  | "protectedDenials"
  | "rateLimited"
  | "successes";

type ThresholdExpression =
  | { metric: InternalMetricName; op: "gte"; value: number }
  | {
      basisPoints: number;
      denominator: "denominator";
      minDenominator: number;
      minNumerator: number;
      numerator: "numerator";
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
  resolutionMode: AlertResolutionMode;
  source: AlertSourceDescriptor;
  sourceKind: AlertSourceKind;
  thresholds: Readonly<Record<AlertWindowKey, WindowThresholdDefinition>>;
}

const countAtLeast = (
  metric: InternalMetricName,
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

const automatic = "automatic" as const;
const d1Exact = "d1_exact" as const;

export const ALERT_RULE_DEFINITIONS = {
  "pgid.registration.rate_limited.v1": {
    dimensions: ["global"],
    id: "pgid.registration.rate_limited.v1",
    resolutionMode: automatic,
    source: {
      ...AUDIT_EVENT_SOURCE_COLUMNS,
      dimensionColumn: null,
      filters: [{
        eventTypes: ["registration.rate_limited"],
        metricRoles: ["count"],
        outcome: "denied",
      }],
      includeGlobal: true,
      mode: "audit_event",
      table: "audit_event",
    },
    sourceKind: d1Exact,
    thresholds: {
      "5m": { critical: null, warning: countAtLeast("count", 5) },
      "15m": { critical: null, warning: countAtLeast("count", 10) },
      "60m": { critical: countAtLeast("count", 40), warning: null },
    },
  },
  "pgid.registration.denied.v1": {
    dimensions: ["global"],
    id: "pgid.registration.denied.v1",
    resolutionMode: automatic,
    source: {
      ...AUDIT_EVENT_SOURCE_COLUMNS,
      dimensionColumn: null,
      filters: [{
        eventTypes: ["registration.denied"],
        metricRoles: ["count"],
        outcome: "denied",
      }],
      includeGlobal: true,
      mode: "audit_event",
      table: "audit_event",
    },
    sourceKind: d1Exact,
    thresholds: {
      "5m": { critical: null, warning: countAtLeast("count", 10) },
      "15m": { critical: null, warning: countAtLeast("count", 25) },
      "60m": { critical: countAtLeast("count", 100), warning: null },
    },
  },
  "pgid.registration.challenge_unavailable.v1": {
    dimensions: ["global"],
    id: "pgid.registration.challenge_unavailable.v1",
    resolutionMode: automatic,
    source: {
      ...AUDIT_EVENT_SOURCE_COLUMNS,
      dimensionColumn: null,
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
      mode: "audit_event",
      table: "audit_event",
    },
    sourceKind: d1Exact,
    thresholds: {
      "5m": { critical: null, warning: ratioAtLeast(5, 2, 2_000) },
      "15m": { critical: null, warning: ratioAtLeast(15, 2, 2_000) },
      "60m": {
        critical: ratioAtLeast(30, 5, 5_000),
        warning: null,
      },
    },
  },
  "pgid.registration.restricted_created.v1": {
    dimensions: ["global"],
    id: "pgid.registration.restricted_created.v1",
    resolutionMode: automatic,
    source: {
      ...AUDIT_EVENT_SOURCE_COLUMNS,
      dimensionColumn: null,
      filters: [{
        eventTypes: ["user.created"],
        metadata: { key: "accessLevel", values: ["restricted"] },
        metricRoles: ["count"],
        outcome: "success",
      }],
      includeGlobal: true,
      mode: "audit_event",
      table: "audit_event",
    },
    sourceKind: d1Exact,
    thresholds: {
      "5m": { critical: null, warning: countAtLeast("count", 7) },
      "15m": { critical: null, warning: countAtLeast("count", 20) },
      "60m": { critical: countAtLeast("count", 80), warning: null },
    },
  },
  "pgid.restricted.sensitive_denied.v1": {
    dimensions: ["subject_hmac"],
    id: "pgid.restricted.sensitive_denied.v1",
    resolutionMode: automatic,
    source: {
      ...AUDIT_EVENT_SOURCE_COLUMNS,
      dimensionColumn: "subject_id",
      filters: [{
        eventTypes: ["account.restricted_action_denied"],
        metadata: { key: "surface", values: RESTRICTED_ALERT_SURFACES },
        metricRoles: ["count", "known_surfaces"],
        outcome: "denied",
      }],
      includeGlobal: false,
      mode: "audit_event",
      table: "audit_event",
    },
    sourceKind: d1Exact,
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
        warning: null,
      },
    },
  },
  "pgid.recovery.entry_abuse.v1": {
    dimensions: ["global"],
    id: "pgid.recovery.entry_abuse.v1",
    resolutionMode: automatic,
    source: {
      ...AUDIT_EVENT_SOURCE_COLUMNS,
      dimensionColumn: null,
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
      mode: "audit_event",
      table: "audit_event",
    },
    sourceKind: d1Exact,
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
    resolutionMode: automatic,
    source: {
      ...AUDIT_EVENT_SOURCE_COLUMNS,
      dimensionColumn: "subject_id",
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
      mode: "audit_event",
      table: "audit_event",
    },
    sourceKind: d1Exact,
    thresholds: {
      "5m": { critical: null, warning: ratioAtLeast(3, 3, 6_000) },
      "15m": { critical: null, warning: ratioAtLeast(5, 5, 6_000) },
      "60m": {
        critical: ratioAtLeast(10, 10, 8_000),
        warning: null,
      },
    },
  },
  "pgid.passkey.step_up_failure.v1": {
    dimensions: ["global", "subject_hmac"],
    id: "pgid.passkey.step_up_failure.v1",
    resolutionMode: automatic,
    source: {
      ...AUDIT_EVENT_SOURCE_COLUMNS,
      dimensionColumn: "subject_id",
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
      mode: "audit_event",
      table: "audit_event",
    },
    sourceKind: d1Exact,
    thresholds: {
      "5m": { critical: null, warning: ratioAtLeast(5, 3, 3_000) },
      "15m": { critical: null, warning: ratioAtLeast(15, 5, 3_000) },
      "60m": {
        critical: ratioAtLeast(30, 10, 6_000),
        warning: null,
      },
    },
  },
  "pgid.oauth.client_report.v1": {
    dimensions: ["client_hmac"],
    id: "pgid.oauth.client_report.v1",
    resolutionMode: automatic,
    source: {
      allReasons: OAUTH_REPORT_REASONS,
      completenessPredicate: "reporter_user_id_or_reporter_ref_present",
      coverageLookbackSeconds: 3_600,
      createdAtColumn: "created_at",
      dimensionColumn: "client_id",
      hashVersion: 1,
      highRiskReasons: HIGH_RISK_OAUTH_REPORT_REASONS,
      missingReporterIdentity: "null_distinct_reporters",
      mode: "oauth_client_report",
      reasonColumn: "reason",
      reporterRefColumn: "reporter_ref",
      reporterRefDomain: "reporter_hmac",
      reporterRefHashVersionColumn: "reporter_ref_hash_version",
      reporterUserIdColumn: "reporter_user_id",
      table: "oauth_client_report",
    },
    sourceKind: d1Exact,
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
        warning: null,
      },
    },
  },
  "pgid.admin.sensitive_activity.v1": {
    dimensions: ["actor_hmac"],
    id: "pgid.admin.sensitive_activity.v1",
    resolutionMode: automatic,
    source: {
      ...AUDIT_EVENT_SOURCE_COLUMNS,
      actorRefColumn: "actor_ref",
      actorRefHashVersionColumn: "actor_ref_hash_version",
      completenessPredicate: "actor_user_id_or_actor_ref_present",
      coverageLookbackSeconds: 3_600,
      dimensionColumn: "actor_user_id",
      filters: [
        {
          eventTypes: HIGH_RISK_ADMIN_SUCCESS_EVENTS,
          metricRoles: ["count", "successes"],
          outcome: "success",
        },
        {
          eventTypes: BOOTADMIN_PROTECTED_EVENTS,
          metadata: { key: "reason", values: ["bootadmin_protected"] },
          metricRoles: ["count", "protected_denials"],
          outcome: "denied",
        },
      ],
      includeGlobal: false,
      mode: "audit_event",
      missingActorIdentity: "source_incomplete",
      table: "audit_event",
    },
    sourceKind: d1Exact,
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
    resolutionMode: automatic,
    source: {
      ...AUDIT_EVENT_SOURCE_COLUMNS,
      actorRefColumn: "actor_ref",
      actorRefHashVersionColumn: "actor_ref_hash_version",
      completenessPredicate: "actor_user_id_or_actor_ref_present",
      coverageLookbackSeconds: 3_600,
      dimensionColumn: "actor_user_id",
      filters: [{
        eventTypes: ["admin.users_listed"],
        metricRoles: ["count"],
        outcome: "success",
      }],
      includeGlobal: false,
      mode: "audit_event",
      missingActorIdentity: "source_incomplete",
      table: "audit_event",
    },
    sourceKind: d1Exact,
    thresholds: {
      "5m": { critical: null, warning: countAtLeast("count", 20) },
      "15m": { critical: null, warning: countAtLeast("count", 50) },
      "60m": { critical: countAtLeast("count", 200), warning: null },
    },
  },
  "pgid.security.fanout_gap.v1": {
    dimensions: ["global"],
    id: "pgid.security.fanout_gap.v1",
    resolutionMode: "manual",
    source: {
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
    sourceKind: d1Exact,
    thresholds: {
      "5m": {
        critical: null,
        warning: countAtLeast("missingOlderThan5mCount", 1),
      },
      "15m": {
        critical: countAtLeast("missingOlderThan15mCount", 1),
        warning: null,
      },
      "60m": {
        critical: countAtLeast("missingOlderThan5mCount", 10),
        warning: null,
      },
    },
  },
  "pgid.logout.delivery_health.v1": {
    dimensions: ["global", "client_hmac"],
    id: "pgid.logout.delivery_health.v1",
    resolutionMode: automatic,
    source: {
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
    sourceKind: d1Exact,
    thresholds: {
      "5m": {
        critical: anyOf(
          countAtLeast("dead", 1),
          ratioAtLeast(5, 1, 5_000),
        ),
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
    resolutionMode: automatic,
    source: {
      dimension: "global",
      evaluator: {
        ageSecondsSemantics: "as_of_minus_last_success_at_floor_seconds",
        bootstrap: {
          completenessLayer: "repository_source",
          completenessParser: "parseAlertRuntimeSourceCompleteness",
          enablement: "one_way_immutable_repository_sentinel",
          insertion: "same_atomic_d1_batch_repository_insert_select_after_controlled_success",
          parserAttestation: "shape_and_chronology_only",
          postBootstrapInvalidDisposition: "emit_missing_threshold_input",
          postBootstrapStatuses: [
            "disabled",
            "healthy",
            "degraded",
            "failing",
            "unavailable",
          ],
          preBootstrapDisposition: "exclude_without_threshold_input",
          provenance: "schema_guards_and_repository_query",
          query: {
            access: "repository_only",
            anchor: "SELECT 'evaluator' AS expected_component",
            bootstrapJoin:
              "LEFT JOIN alert_evaluator_bootstrap AS b ON b.component = e.expected_component",
            projection: {
              bootstrapComponent: "b.component AS bootstrap_component",
              firstSuccessAt: "b.first_success_at AS first_success_at",
              runtimeComponent: "r.component AS runtime_component",
              runtimeGeneration: "r.generation AS runtime_generation",
              runtimeLastErrorAt: "r.last_error_at AS runtime_last_error_at",
              runtimeLastErrorCode:
                "r.last_error_code AS runtime_last_error_code",
              runtimeLastStartedAt:
                "r.last_started_at AS runtime_last_started_at",
              runtimeLastSuccessAt:
                "r.last_success_at AS runtime_last_success_at",
              runtimeRevision: "r.revision AS runtime_revision",
              runtimeStatus: "r.status AS runtime_status",
              runtimeUpdatedAt: "r.updated_at AS runtime_updated_at",
              sourceGeneration: "b.source_generation AS source_generation",
              sourceRevision: "b.source_revision AS source_revision",
            },
            repositoryQuery: ALERT_RUNTIME_SOURCE_QUERY,
            runtimeJoin:
              "LEFT JOIN alert_runtime_status AS r ON r.component = e.expected_component",
          },
          sentinel: {
            columns: {
              component: "component",
              firstSuccessAt: "first_success_at",
              sourceGeneration: "source_generation",
              sourceRevision: "source_revision",
            },
            component: "evaluator",
            foreignKey: {
              column: "component",
              onDelete: "restrict",
              referencedColumn: "component",
              referencedTable: "alert_runtime_status",
            },
            immutable: true,
            singleton: true,
            table: "alert_evaluator_bootstrap",
          },
          statusAlone: "never_sufficient",
        },
        component: "evaluator",
        componentColumn: "component",
        lastSuccessAtColumn: "last_success_at",
        nullAgeSemantics: "post_bootstrap_evaluator_missing_only",
        runtimeStatuses: [
          "disabled",
          "healthy",
          "degraded",
          "failing",
          "unavailable",
        ],
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
      thresholdInput: {
        bootstrapFields: "forbidden",
        evaluatorAgeSecondsNull: "post_bootstrap_missing_immediate",
        preBootstrap: "no_observation",
      },
    },
    sourceKind: d1Exact,
    thresholds: {
      "5m": {
        critical: null,
        warning: anyOf(
          countAtLeast("evaluatorAgeSeconds", 181),
          countAtLeast("outboxDueAgeSeconds", 121),
        ),
      },
      "15m": {
        critical: anyOf(
          countAtLeast("evaluatorMissing", 1),
          countAtLeast("evaluatorAgeSeconds", 301),
          countAtLeast("outboxDueAgeSeconds", 301),
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
    resolutionMode: automatic,
    source: {
      backlogBytesBindingField: "backlogBytes",
      backlogBytesColumn: "backlog_bytes",
      backlogBytesMaximum: MAX_QUEUE_BACKLOG_BYTES,
      backlogCountBindingField: "backlogCount",
      backlogCountColumn: "backlog_count",
      backlogCountMaximum: MAX_EVIDENCE_VALUE,
      componentColumn: "component",
      consecutiveNonzeroSamplesColumn: "consecutive_nonzero_samples",
      consecutiveNonzeroSamplesMaximum: MAX_RATIO_FIELD,
      criticalDurationSeconds: 900,
      dimension: "queue_name",
      invalidBindingMetrics: "unknown",
      method: "metrics",
      metricSampledAtColumn: "metric_sampled_at",
      mode: "queue_metrics",
      nonzeroSinceAtColumn: "nonzero_since_at",
      numericValidation: "finite_safe_nonnegative_integer",
      oldestMessageAgeSecondsColumn: "oldest_message_age_seconds",
      oldestMessageAgeSecondsMaximum: MAX_EVIDENCE_VALUE,
      oldestMessageTimestampBindingField: "oldestMessageTimestamp",
      oldestMessageTimestampNormalization: "sampled_at_minus_oldest_message_timestamp_floor_seconds",
      queueComponentByName: ALERT_QUEUE_COMPONENTS,
      queueNames: ALERT_QUEUE_NAMES,
      sampleCadenceSeconds: 60,
      streakStateTable: "alert_runtime_status",
    },
    sourceKind: "queue_approximate",
    thresholds: {
      "5m": { critical: null, warning: countAtLeast("depth", 1) },
      "15m": {
        critical: anyOf(
          countAtLeast("depth", 10),
          countAtLeast("consecutiveNonzeroSamples", 15),
        ),
        warning: null,
      },
      "60m": { critical: null, warning: null },
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
> {
  asOf: string;
  dimension: Dimension;
  ruleId: RuleId;
}

interface WindowObservationBase<
  RuleId extends AlertRuleId,
  Dimension extends AlertDimension,
  Metrics,
> extends ObservationBase<RuleId, Dimension> {
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
  distinctReporters: number | null;
  highRiskCount: number;
}

export interface AdminSensitiveWindowMetrics {
  protectedDenials: number;
  successes: number;
}

export interface FanoutGapSnapshot {
  missingOlderThan15mCount: number;
  missingOlderThan5mCount: number;
}

export interface LogoutDeliveryCurrentSnapshot {
  currentDead: number;
  currentUnresolved: number;
  oldestUnresolvedAgeSeconds: number | null;
}

export interface LogoutDeliveryWindowMetrics {
  eligible: number;
  leaseExpired: number;
  unresolved: number;
}

export interface AlertRuntimeSnapshot {
  deadOutbox: number;
  evaluatorAgeSeconds: number | null;
  outboxDueAgeSeconds: number | null;
}

export interface QueueDepthSnapshot {
  backlogBytes: number | null;
  backlogCount: number | null;
  consecutiveNonzeroSamples: number | null;
  nonzeroSinceAt: string | null;
  oldestMessageTimestamp: string | null;
  sampledAt: string | null;
}

type GlobalCountRuleId =
  | "pgid.registration.rate_limited.v1"
  | "pgid.registration.denied.v1"
  | "pgid.registration.restricted_created.v1";

export type AlertRuleObservation =
  | WindowObservationBase<
      GlobalCountRuleId,
      { kind: "global" },
      CountWindowMetrics
    >
  | WindowObservationBase<
      "pgid.registration.challenge_unavailable.v1",
      { kind: "global" },
      RatioWindowMetrics
    >
  | WindowObservationBase<
      "pgid.restricted.sensitive_denied.v1",
      Extract<AlertDimension, { kind: "subject_hmac" }>,
      RestrictedDenialWindowMetrics
    >
  | WindowObservationBase<
      "pgid.recovery.entry_abuse.v1",
      { kind: "global" },
      RecoveryEntryWindowMetrics
    >
  | WindowObservationBase<
      | "pgid.recovery.passkey_failure.v1"
      | "pgid.passkey.step_up_failure.v1",
      { kind: "global" } | Extract<AlertDimension, { kind: "subject_hmac" }>,
      RatioWindowMetrics
    >
  | WindowObservationBase<
      "pgid.oauth.client_report.v1",
      Extract<AlertDimension, { kind: "client_hmac" }>,
      OAuthClientReportWindowMetrics
    >
  | WindowObservationBase<
      "pgid.admin.sensitive_activity.v1",
      Extract<AlertDimension, { kind: "actor_hmac" }>,
      AdminSensitiveWindowMetrics
    >
  | WindowObservationBase<
      "pgid.admin.directory_volume.v1",
      Extract<AlertDimension, { kind: "actor_hmac" }>,
      CountWindowMetrics
    >
  | (ObservationBase<
      "pgid.security.fanout_gap.v1",
      { kind: "global" }
    > & { snapshot: FanoutGapSnapshot })
  | (WindowObservationBase<
      "pgid.logout.delivery_health.v1",
      { kind: "global" } | Extract<AlertDimension, { kind: "client_hmac" }>,
      LogoutDeliveryWindowMetrics
    > & { current: LogoutDeliveryCurrentSnapshot })
  | (ObservationBase<
      "pgid.alert.runtime_health.v1",
      { kind: "global" }
    > & { snapshot: AlertRuntimeSnapshot })
  | (ObservationBase<
      "pgid.queue.dlq_approximate.v1",
      Extract<AlertDimension, { kind: "queue" }>
    > & { snapshot: QueueDepthSnapshot });

interface MetricBag {
  consecutiveNonzeroSamples?: number;
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
  missingOlderThan15mCount?: number;
  missingOlderThan5mCount?: number;
  numerator?: number;
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
  kind: AlertEvidenceMetricKind;
  metricName: AlertMetricName;
  minimumNumeratorCount: number | null;
  minimumSampleCount: number;
  observedDenominator: number | null;
  observedNumerator: number | null;
  observedValue: number;
  threshold: number;
  unit: AlertEvidenceUnit;
}

export interface AlertSelectedEvidence extends AlertMetricEvidence {
  secondary: AlertMetricEvidence | null;
  severity: Exclude<AlertSeverity, "none">;
  windowSeconds: 300 | 900 | 3_600;
}

const ALERT_METRIC_NAME_SET = new Set<string>([
  "consecutive_nonzero_samples",
  "count",
  "dead",
  "dead_outbox",
  "depth",
  "distinct_reporters",
  "evaluator_age_seconds",
  "evaluator_missing",
  "high_risk_count",
  "known_surfaces",
  "lease_expired",
  "missing",
  "oldest_unresolved_age_seconds",
  "outbox_due_age_seconds",
  "protected_denials",
  "rate_limited",
  "ratio",
  "successes",
]);

function metricDomain(metricName: AlertMetricName): {
  kind: AlertEvidenceMetricKind;
  unit: AlertEvidenceUnit;
} {
  if (metricName === "ratio") {
    return { kind: "ratio", unit: "basis_points" };
  }
  if (
    metricName === "evaluator_age_seconds" ||
    metricName === "oldest_unresolved_age_seconds" ||
    metricName === "outbox_due_age_seconds"
  ) {
    return { kind: "age_seconds", unit: "seconds" };
  }
  if (metricName === "consecutive_nonzero_samples") {
    return { kind: "consecutive", unit: "samples" };
  }
  if (metricName === "evaluator_missing") {
    return { kind: "boolean", unit: "state" };
  }
  return { kind: "count", unit: "events" };
}

function parseMetricEvidence(value: unknown, name: string): AlertMetricEvidence {
  const record = exactRecord(
    value,
    [
      "kind",
      "metricName",
      "minimumNumeratorCount",
      "minimumSampleCount",
      "observedDenominator",
      "observedNumerator",
      "observedValue",
      "threshold",
      "unit",
    ],
    name,
  );
  if (
    typeof record.metricName !== "string" ||
    !ALERT_METRIC_NAME_SET.has(record.metricName)
  ) {
    throw new Error(`${name} metric name is not supported`);
  }
  const metricName = record.metricName as AlertMetricName;
  const domain = metricDomain(metricName);
  if (record.kind !== domain.kind || record.unit !== domain.unit) {
    throw new Error(`${name} metric domain is inconsistent`);
  }
  const observedValue = integer(record.observedValue, `${name} observed value`);
  const threshold = integer(record.threshold, `${name} threshold`);
  if (threshold < 1) throw new Error(`${name} threshold must be positive`);
  if (metricName === "ratio") {
    const observedNumerator = integer(
      record.observedNumerator,
      `${name} observed numerator`,
      MAX_RATIO_FIELD,
    );
    const observedDenominator = integer(
      record.observedDenominator,
      `${name} observed denominator`,
      MAX_RATIO_FIELD,
    );
    const minimumSampleCount = integer(
      record.minimumSampleCount,
      `${name} minimum sample count`,
      MAX_RATIO_FIELD,
    );
    const minimumNumeratorCount = integer(
      record.minimumNumeratorCount,
      `${name} minimum numerator count`,
      MAX_RATIO_FIELD,
    );
    if (
      observedDenominator < 1 ||
      minimumNumeratorCount < 1 ||
      observedNumerator > observedDenominator ||
      observedDenominator < minimumSampleCount ||
      observedNumerator < minimumNumeratorCount ||
      observedValue !== Math.floor(observedNumerator * 10_000 / observedDenominator) ||
      threshold > 10_000
    ) {
      throw new Error(`${name} ratio evidence is inconsistent`);
    }
    return {
      kind: domain.kind,
      metricName,
      minimumNumeratorCount,
      minimumSampleCount,
      observedDenominator,
      observedNumerator,
      observedValue,
      threshold,
      unit: domain.unit,
    };
  }
  if (
    record.observedNumerator !== null ||
    record.observedDenominator !== null ||
    record.minimumNumeratorCount !== null ||
    record.minimumSampleCount !== 0
  ) {
    throw new Error(`${name} non-ratio evidence has ratio fields`);
  }
  if (metricName === "evaluator_missing" && observedValue > 1) {
    throw new Error(`${name} boolean evidence is inconsistent`);
  }
  return {
    kind: domain.kind,
    metricName,
    minimumNumeratorCount: null,
    minimumSampleCount: 0,
    observedDenominator: null,
    observedNumerator: null,
    observedValue,
    threshold,
    unit: domain.unit,
  };
}

export function parseAlertSelectedEvidence(value: unknown): AlertSelectedEvidence {
  const record = exactRecord(
    value,
    [
      "kind",
      "metricName",
      "minimumNumeratorCount",
      "minimumSampleCount",
      "observedDenominator",
      "observedNumerator",
      "observedValue",
      "secondary",
      "severity",
      "threshold",
      "unit",
      "windowSeconds",
    ],
    "selected alert evidence",
  );
  const primary = parseMetricEvidence(
    {
      kind: record.kind,
      metricName: record.metricName,
      minimumNumeratorCount: record.minimumNumeratorCount,
      minimumSampleCount: record.minimumSampleCount,
      observedDenominator: record.observedDenominator,
      observedNumerator: record.observedNumerator,
      observedValue: record.observedValue,
      threshold: record.threshold,
      unit: record.unit,
    },
    "primary alert evidence",
  );
  if (record.severity !== "warning" && record.severity !== "critical") {
    throw new Error("selected alert evidence severity is not supported");
  }
  if (
    record.windowSeconds !== 300 &&
    record.windowSeconds !== 900 &&
    record.windowSeconds !== 3_600
  ) {
    throw new Error("selected alert evidence window is not supported");
  }
  const secondary = record.secondary === null
    ? null
    : parseMetricEvidence(record.secondary, "secondary alert evidence");
  if (
    primary.metricName === "known_surfaces" ||
    primary.metricName === "distinct_reporters" ||
    primary.observedValue < primary.threshold
  ) {
    throw new Error("primary alert evidence does not prove a canonical breach");
  }
  if (secondary !== null) {
    const pair = `${primary.metricName}|${secondary.metricName}`;
    if (
      pair !== "count|known_surfaces" &&
      pair !== "high_risk_count|distinct_reporters"
    ) {
      throw new Error("selected alert evidence component pair is not supported");
    }
    if (secondary.observedValue < secondary.threshold) {
      throw new Error("secondary alert evidence does not prove a canonical breach");
    }
  }
  return {
    ...primary,
    secondary,
    severity: record.severity,
    windowSeconds: record.windowSeconds,
  };
}

interface AlertEvidenceContractComponent {
  metricName: AlertMetricName;
  minimumNumeratorCount: number | null;
  minimumSampleCount: number;
  threshold: number;
}

function evidenceContractsFor(
  expression: ThresholdExpression,
): readonly (readonly AlertEvidenceContractComponent[])[] {
  if (expression.op === "gte") {
    return [[{
      metricName: METRIC_NAMES[expression.metric],
      minimumNumeratorCount: null,
      minimumSampleCount: 0,
      threshold: expression.value,
    }]];
  }
  if (expression.op === "ratio_gte") {
    return [[{
      metricName: "ratio",
      minimumNumeratorCount: expression.minNumerator,
      minimumSampleCount: expression.minDenominator,
      threshold: expression.basisPoints,
    }]];
  }
  if (expression.op === "any") {
    return expression.clauses.flatMap((clause) => evidenceContractsFor(clause));
  }
  let combined: readonly (readonly AlertEvidenceContractComponent[])[] = [[]];
  for (const clause of expression.clauses) {
    const clauseContracts = evidenceContractsFor(clause);
    combined = combined.flatMap((prefix) =>
      clauseContracts.map((suffix) => [...prefix, ...suffix])
    );
  }
  return combined;
}

function evidenceMatchesContract(
  evidence: AlertSelectedEvidence,
  contract: readonly AlertEvidenceContractComponent[],
): boolean {
  const actual = evidence.secondary === null
    ? [evidence]
    : [evidence, evidence.secondary];
  return actual.length === contract.length && actual.every((component, index) => {
    const expected = contract[index];
    return expected !== undefined &&
      component.metricName === expected.metricName &&
      component.minimumNumeratorCount === expected.minimumNumeratorCount &&
      component.minimumSampleCount === expected.minimumSampleCount &&
      component.threshold === expected.threshold;
  });
}

export function parseAlertSelectedEvidenceForRule(
  value: unknown,
  ruleId: AlertRuleId,
): AlertSelectedEvidence {
  const evidence = parseAlertSelectedEvidence(value);
  const window = evidence.windowSeconds === 300
    ? "5m"
    : evidence.windowSeconds === 900
      ? "15m"
      : "60m";
  const expression = ALERT_RULE_DEFINITIONS[ruleId].thresholds[window][evidence.severity];
  if (
    expression === null ||
    !evidenceContractsFor(expression).some((contract) =>
      evidenceMatchesContract(evidence, contract)
    )
  ) {
    throw new Error("selected alert evidence does not match the canonical rule contract");
  }
  return evidence;
}

export function parseAlertRuleId(value: unknown): AlertRuleId {
  if (typeof value !== "string" || !RULE_ID_SET.has(value)) {
    throw new Error("alert rule id is not supported");
  }
  return value as AlertRuleId;
}

export function parseAlertDimension(
  value: unknown,
  allowed: readonly AlertDimension["kind"][],
): AlertDimension {
  const record = recordValue(value, "alert dimension");
  const kind = record.kind;
  if (kind === "global") {
    exactRecord(value, ["kind"], "global alert dimension");
    if (!allowed.includes(kind)) throw new Error("alert dimension is not allowed");
    return { kind };
  }
  if (kind === "queue") {
    const exact = exactRecord(value, ["kind", "queue"], "Queue alert dimension");
    if (!allowed.includes(kind)) throw new Error("alert dimension is not allowed");
    if (typeof exact.queue !== "string" || !ALERT_QUEUE_NAME_SET.has(exact.queue)) {
      throw new Error("alert Queue name is not supported");
    }
    return { kind, queue: exact.queue as AlertQueueName };
  }
  if (typeof kind === "string" && HASHED_DIMENSION_KIND_SET.has(kind)) {
    const exact = exactRecord(
      value,
      ["kind", "reference"],
      "hashed alert dimension",
    );
    if (!allowed.includes(kind as AlertDimension["kind"])) {
      throw new Error("alert dimension is not allowed");
    }
    return {
      kind: kind as AlertHashedDimensionKind,
      reference: parseHashedReference(exact.reference),
    };
  }
  throw new Error("alert dimension kind is not supported");
}

function integer(
  value: unknown,
  name: string,
  maximum = MAX_EVIDENCE_VALUE,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > maximum) {
    throw new Error(`${name} must be an integer in the persistence domain`);
  }
  return value as number;
}

function nullableInteger(
  value: unknown,
  name: string,
  maximum = MAX_EVIDENCE_VALUE,
): number | null {
  return value === null ? null : integer(value, name, maximum);
}

function queueBindingInteger(
  value: unknown,
  maximum: number,
): { valid: boolean; value: number | null } {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > maximum) {
    return { valid: false, value: null };
  }
  return { valid: true, value: value as number };
}

function queueBindingTimestamp(
  value: unknown,
): { valid: boolean; value: string | null } {
  if (value === undefined || value === null) return { valid: true, value: null };
  if (value instanceof Date) {
    const timestamp = value.getTime();
    return Number.isFinite(timestamp)
      ? { valid: true, value: new Date(timestamp).toISOString() }
      : { valid: false, value: null };
  }
  try {
    return { valid: true, value: canonicalTimestamp(value, "oldestMessageTimestamp") };
  } catch {
    return { valid: false, value: null };
  }
}

function parseCountMetrics(value: unknown): CountWindowMetrics {
  const record = exactRecord(value, ["count"], "count metrics");
  return { count: integer(record.count, "count") };
}

function parseRatioMetrics(value: unknown): RatioWindowMetrics {
  const record = exactRecord(value, ["denominator", "numerator"], "ratio metrics");
  const denominator = integer(record.denominator, "denominator", MAX_RATIO_FIELD);
  const numerator = integer(record.numerator, "numerator", MAX_RATIO_FIELD);
  if (numerator > denominator) throw new Error("numerator cannot exceed denominator");
  return { denominator, numerator };
}

function parseRestrictedMetrics(value: unknown): RestrictedDenialWindowMetrics {
  const record = exactRecord(value, ["count", "knownSurfaces"], "restricted metrics");
  const count = integer(record.count, "count");
  const knownSurfaces = integer(record.knownSurfaces, "known surfaces");
  if (
    knownSurfaces > count ||
    knownSurfaces > RESTRICTED_ALERT_SURFACES.length
  ) {
    throw new Error("known surfaces exceed the canonical denied-event domain");
  }
  return { count, knownSurfaces };
}

function parseRecoveryEntryMetrics(value: unknown): RecoveryEntryWindowMetrics {
  const record = exactRecord(
    value,
    ["denied", "rateLimited", "started"],
    "recovery entry metrics",
  );
  const denied = integer(record.denied, "denied", MAX_RATIO_FIELD);
  const rateLimited = integer(record.rateLimited, "rate limited");
  const started = integer(record.started, "started", MAX_RATIO_FIELD);
  if (denied + started > MAX_RATIO_FIELD) {
    throw new Error("recovery denominator exceeds the persistence domain");
  }
  return { denied, rateLimited, started };
}

function parseOAuthMetrics(value: unknown): OAuthClientReportWindowMetrics {
  const record = exactRecord(
    value,
    ["count", "distinctReporters", "highRiskCount"],
    "OAuth report metrics",
  );
  const count = integer(record.count, "report count");
  const distinctReporters = nullableInteger(
    record.distinctReporters,
    "distinct reporters",
  );
  const highRiskCount = integer(record.highRiskCount, "high-risk count");
  if ((distinctReporters !== null && distinctReporters > count) || highRiskCount > count) {
    throw new Error("OAuth report subsets cannot exceed total reports");
  }
  return { count, distinctReporters, highRiskCount };
}

function parseAdminSensitiveMetrics(value: unknown): AdminSensitiveWindowMetrics {
  const record = exactRecord(
    value,
    ["protectedDenials", "successes"],
    "admin-sensitive metrics",
  );
  const protectedDenials = integer(record.protectedDenials, "protected denials");
  const successes = integer(record.successes, "sensitive successes");
  if (protectedDenials + successes > MAX_EVIDENCE_VALUE) {
    throw new Error("admin-sensitive total exceeds the persistence domain");
  }
  return { protectedDenials, successes };
}

function parseLogoutCurrentSnapshot(value: unknown): LogoutDeliveryCurrentSnapshot {
  const record = exactRecord(
    value,
    ["currentDead", "currentUnresolved", "oldestUnresolvedAgeSeconds"],
    "logout-delivery current snapshot",
  );
  const currentDead = integer(record.currentDead, "current dead deliveries");
  const currentUnresolved = integer(
    record.currentUnresolved,
    "current unresolved deliveries",
  );
  const oldestUnresolvedAgeSeconds = nullableInteger(
    record.oldestUnresolvedAgeSeconds,
    "oldest unresolved age",
  );
  if (currentDead > currentUnresolved) {
    throw new Error("current dead deliveries cannot exceed current unresolved deliveries");
  }
  if ((currentUnresolved === 0) !== (oldestUnresolvedAgeSeconds === null)) {
    throw new Error("current unresolved count and oldest age must agree");
  }
  return { currentDead, currentUnresolved, oldestUnresolvedAgeSeconds };
}

function parseLogoutMetrics(value: unknown): LogoutDeliveryWindowMetrics {
  const record = exactRecord(
    value,
    ["eligible", "leaseExpired", "unresolved"],
    "logout-delivery window metrics",
  );
  const eligible = integer(record.eligible, "eligible deliveries", MAX_RATIO_FIELD);
  const leaseExpired = integer(record.leaseExpired, "expired leases");
  const unresolved = integer(record.unresolved, "unresolved deliveries", MAX_RATIO_FIELD);
  if (unresolved > eligible) {
    throw new Error("logout unresolved deliveries cannot exceed their window cohort");
  }
  return { eligible, leaseExpired, unresolved };
}

function parseWindows<T>(
  value: unknown,
  parser: (entry: unknown) => T,
): Windowed<T> {
  const record = exactRecord(value, ALERT_WINDOW_KEYS, "alert windows");
  return {
    "5m": parser(record["5m"]),
    "15m": parser(record["15m"]),
    "60m": parser(record["60m"]),
  };
}

function nondecreasing(values: readonly number[], name: string): void {
  for (let index = 1; index < values.length; index += 1) {
    if (values[index] < values[index - 1]) {
      throw new Error(`${name} must be nondecreasing across nested windows`);
    }
  }
}

function nullableCountNondecreasing(
  values: readonly (number | null)[],
  name: string,
): void {
  let previous: number | null = null;
  let unknownSeen = false;
  for (const value of values) {
    if (value === null) {
      unknownSeen = true;
      continue;
    }
    if (unknownSeen || (previous !== null && value < previous)) {
      throw new Error(`${name} must be nondecreasing or remain unknown across windows`);
    }
    previous = value;
  }
}

function validateNestedWindows(
  ruleId: AlertRuleId,
  windows: Windowed<
    | AdminSensitiveWindowMetrics
    | CountWindowMetrics
    | LogoutDeliveryWindowMetrics
    | OAuthClientReportWindowMetrics
    | RatioWindowMetrics
    | RecoveryEntryWindowMetrics
    | RestrictedDenialWindowMetrics
  >,
): void {
  const entries = ALERT_WINDOW_KEYS.map((key) => windows[key]);
  switch (ruleId) {
    case "pgid.registration.rate_limited.v1":
    case "pgid.registration.denied.v1":
    case "pgid.registration.restricted_created.v1":
    case "pgid.admin.directory_volume.v1":
      nondecreasing(entries.map((entry) => (entry as CountWindowMetrics).count), "count");
      break;
    case "pgid.registration.challenge_unavailable.v1":
    case "pgid.recovery.passkey_failure.v1":
    case "pgid.passkey.step_up_failure.v1":
      nondecreasing(entries.map((entry) => (entry as RatioWindowMetrics).numerator), "numerator");
      nondecreasing(entries.map((entry) => (entry as RatioWindowMetrics).denominator), "denominator");
      break;
    case "pgid.restricted.sensitive_denied.v1":
      nondecreasing(entries.map((entry) => (entry as RestrictedDenialWindowMetrics).count), "count");
      nondecreasing(entries.map((entry) => (entry as RestrictedDenialWindowMetrics).knownSurfaces), "known surfaces");
      break;
    case "pgid.recovery.entry_abuse.v1":
      for (const key of ["denied", "rateLimited", "started"] as const) {
        nondecreasing(
          entries.map((entry) => (entry as RecoveryEntryWindowMetrics)[key]),
          key,
        );
      }
      break;
    case "pgid.oauth.client_report.v1":
      for (const key of ["count", "highRiskCount"] as const) {
        nondecreasing(
          entries.map((entry) => (entry as OAuthClientReportWindowMetrics)[key]),
          key,
        );
      }
      nullableCountNondecreasing(
        entries.map((entry) =>
          (entry as OAuthClientReportWindowMetrics).distinctReporters
        ),
        "distinct reporters",
      );
      break;
    case "pgid.admin.sensitive_activity.v1":
      for (const key of ["protectedDenials", "successes"] as const) {
        nondecreasing(
          entries.map((entry) => (entry as AdminSensitiveWindowMetrics)[key]),
          key,
        );
      }
      break;
    case "pgid.logout.delivery_health.v1": {
      const logout = entries as LogoutDeliveryWindowMetrics[];
      for (const key of ["eligible", "leaseExpired", "unresolved"] as const) {
        nondecreasing(logout.map((entry) => entry[key]), key);
      }
      break;
    }
    default:
      break;
  }
}

function observationBase(
  record: UnknownRecord,
  ruleId: AlertRuleId,
): { asOf: string; dimension: AlertDimension; ruleId: AlertRuleId } {
  const definition = ALERT_RULE_DEFINITIONS[ruleId];
  return {
    asOf: canonicalTimestamp(record.asOf, "asOf"),
    dimension: parseAlertDimension(record.dimension, definition.dimensions),
    ruleId,
  };
}

export function parseAlertObservation(value: unknown): AlertRuleObservation {
  const loose = recordValue(value, "alert observation");
  const ruleId = parseAlertRuleId(loose.ruleId);
  if (ruleId === "pgid.security.fanout_gap.v1") {
    const record = exactRecord(
      value,
      ["asOf", "dimension", "ruleId", "snapshot"],
      "fan-out observation",
    );
    const base = observationBase(record, ruleId);
    if (base.dimension.kind !== "global") {
      throw new Error("fan-out alert dimension must be global");
    }
    const dimension = base.dimension;
    const snapshotRecord = exactRecord(
      record.snapshot,
      ["missingOlderThan15mCount", "missingOlderThan5mCount"],
      "fan-out snapshot",
    );
    const snapshot = {
      missingOlderThan15mCount: integer(
        snapshotRecord.missingOlderThan15mCount,
        "missing older than 15 minutes",
      ),
      missingOlderThan5mCount: integer(
        snapshotRecord.missingOlderThan5mCount,
        "missing older than 5 minutes",
      ),
    };
    if (snapshot.missingOlderThan15mCount > snapshot.missingOlderThan5mCount) {
      throw new Error("fan-out age cohorts are inconsistent");
    }
    return { asOf: base.asOf, dimension, ruleId, snapshot };
  }
  if (ruleId === "pgid.alert.runtime_health.v1") {
    const record = exactRecord(
      value,
      ["asOf", "dimension", "ruleId", "snapshot"],
      "runtime observation",
    );
    const base = observationBase(record, ruleId);
    if (base.dimension.kind !== "global") {
      throw new Error("runtime alert dimension must be global");
    }
    const dimension = base.dimension;
    const snapshotRecord = exactRecord(
      record.snapshot,
      ["deadOutbox", "evaluatorAgeSeconds", "outboxDueAgeSeconds"],
      "runtime snapshot",
    );
    return {
      asOf: base.asOf,
      dimension,
      ruleId,
      snapshot: {
        deadOutbox: integer(snapshotRecord.deadOutbox, "dead alert outbox"),
        evaluatorAgeSeconds: nullableInteger(
          snapshotRecord.evaluatorAgeSeconds,
          "evaluator age",
        ),
        outboxDueAgeSeconds: nullableInteger(
          snapshotRecord.outboxDueAgeSeconds,
          "outbox due age",
        ),
      },
    };
  }
  if (ruleId === "pgid.queue.dlq_approximate.v1") {
    const record = exactRecord(
      value,
      ["asOf", "dimension", "ruleId", "snapshot"],
      "Queue observation",
    );
    const base = observationBase(record, ruleId);
    if (base.dimension.kind !== "queue") {
      throw new Error("Queue alert dimension must name a Queue");
    }
    const dimension = base.dimension;
    const snapshotRecord = recordValue(record.snapshot, "Queue snapshot");
    const queueSnapshotKeys = [
      "backlogBytes",
      "backlogCount",
      "consecutiveNonzeroSamples",
      "nonzeroSinceAt",
      "oldestMessageTimestamp",
      "sampledAt",
    ] as const;
    if (Object.keys(snapshotRecord).some((key) => !queueSnapshotKeys.includes(
      key as (typeof queueSnapshotKeys)[number],
    ))) {
      throw new Error("Queue snapshot must contain only the canonical keys");
    }
    const backlogBytes = queueBindingInteger(
      snapshotRecord.backlogBytes,
      MAX_QUEUE_BACKLOG_BYTES,
    );
    const backlogCount = queueBindingInteger(
      snapshotRecord.backlogCount,
      MAX_EVIDENCE_VALUE,
    );
    const oldestMessageTimestamp = queueBindingTimestamp(
      snapshotRecord.oldestMessageTimestamp,
    );
    const bindingMetricsValid = backlogBytes.valid &&
      backlogCount.valid &&
      oldestMessageTimestamp.valid;
    return {
      asOf: base.asOf,
      dimension,
      ruleId,
      snapshot: {
        backlogBytes: bindingMetricsValid ? backlogBytes.value : null,
        backlogCount: bindingMetricsValid ? backlogCount.value : null,
        consecutiveNonzeroSamples: nullableInteger(
          snapshotRecord.consecutiveNonzeroSamples,
          "consecutive Queue samples",
          MAX_RATIO_FIELD,
        ),
        nonzeroSinceAt: snapshotRecord.nonzeroSinceAt === null
          ? null
          : canonicalTimestamp(snapshotRecord.nonzeroSinceAt, "nonzeroSinceAt"),
        oldestMessageTimestamp: bindingMetricsValid
          ? oldestMessageTimestamp.value
          : null,
        sampledAt: snapshotRecord.sampledAt === null
          ? null
          : canonicalTimestamp(snapshotRecord.sampledAt, "sampledAt"),
      },
    };
  }
  if (ruleId === "pgid.logout.delivery_health.v1") {
    const record = exactRecord(
      value,
      ["asOf", "current", "dimension", "ruleId", "windows"],
      "logout-delivery observation",
    );
    const base = observationBase(record, ruleId);
    if (base.dimension.kind !== "global" && base.dimension.kind !== "client_hmac") {
      throw new Error("logout-delivery alert dimension must be global or client HMAC");
    }
    const dimension = base.dimension;
    const current = parseLogoutCurrentSnapshot(record.current);
    const windows = parseWindows(record.windows, parseLogoutMetrics);
    validateNestedWindows(ruleId, windows);
    return { asOf: base.asOf, current, dimension, ruleId, windows };
  }
  const record = exactRecord(
    value,
    ["asOf", "dimension", "ruleId", "windows"],
    "windowed alert observation",
  );
  const base = observationBase(record, ruleId);
  switch (ruleId) {
    case "pgid.registration.rate_limited.v1":
    case "pgid.registration.denied.v1":
    case "pgid.registration.restricted_created.v1":
    case "pgid.admin.directory_volume.v1": {
      const windows = parseWindows(record.windows, parseCountMetrics);
      validateNestedWindows(ruleId, windows);
      return { ...base, ruleId, windows } as AlertRuleObservation;
    }
    case "pgid.registration.challenge_unavailable.v1":
    case "pgid.recovery.passkey_failure.v1":
    case "pgid.passkey.step_up_failure.v1": {
      const windows = parseWindows(record.windows, parseRatioMetrics);
      validateNestedWindows(ruleId, windows);
      return { ...base, ruleId, windows } as AlertRuleObservation;
    }
    case "pgid.restricted.sensitive_denied.v1": {
      const windows = parseWindows(record.windows, parseRestrictedMetrics);
      validateNestedWindows(ruleId, windows);
      return { ...base, ruleId, windows } as AlertRuleObservation;
    }
    case "pgid.recovery.entry_abuse.v1": {
      const windows = parseWindows(record.windows, parseRecoveryEntryMetrics);
      validateNestedWindows(ruleId, windows);
      return { ...base, ruleId, windows } as AlertRuleObservation;
    }
    case "pgid.oauth.client_report.v1": {
      const windows = parseWindows(record.windows, parseOAuthMetrics);
      validateNestedWindows(ruleId, windows);
      return { ...base, ruleId, windows } as AlertRuleObservation;
    }
    case "pgid.admin.sensitive_activity.v1": {
      const windows = parseWindows(record.windows, parseAdminSensitiveMetrics);
      validateNestedWindows(ruleId, windows);
      return { ...base, ruleId, windows } as AlertRuleObservation;
    }
    default: {
      const exhaustive: never = ruleId;
      throw new Error(`unsupported alert observation: ${String(exhaustive)}`);
    }
  }
}

function countBag(metrics: CountWindowMetrics): MetricBag {
  return { count: metrics.count };
}

function ratioBag(metrics: RatioWindowMetrics): MetricBag {
  return metrics;
}

interface KnownQueueSnapshot {
  backlogBytes: number;
  consecutiveNonzeroSamples: number;
  depth: number;
  oldestMessageAgeSeconds: number;
}

function knownQueueSnapshot(
  snapshot: QueueDepthSnapshot,
  asOf: string,
): KnownQueueSnapshot | null {
  if (
    snapshot.backlogBytes === null ||
    snapshot.backlogCount === null ||
    snapshot.sampledAt === null ||
    snapshot.consecutiveNonzeroSamples === null ||
    snapshot.sampledAt !== asOf
  ) {
    return null;
  }
  if (snapshot.backlogCount === 0) {
    return snapshot.nonzeroSinceAt === null &&
        snapshot.consecutiveNonzeroSamples === 0 &&
        snapshot.backlogBytes === 0 &&
        snapshot.oldestMessageTimestamp === null
      ? {
        backlogBytes: 0,
        consecutiveNonzeroSamples: 0,
        depth: 0,
        oldestMessageAgeSeconds: 0,
      }
      : null;
  }
  if (
    snapshot.nonzeroSinceAt === null ||
    snapshot.consecutiveNonzeroSamples < 1 ||
    snapshot.oldestMessageTimestamp === null
  ) {
    return null;
  }
  const sampledAt = new Date(snapshot.sampledAt).getTime();
  const oldestMessageAgeMilliseconds = sampledAt -
    new Date(snapshot.oldestMessageTimestamp).getTime();
  if (oldestMessageAgeMilliseconds < 0) return null;
  const oldestMessageAgeSeconds = Math.floor(oldestMessageAgeMilliseconds / 1_000);
  if (oldestMessageAgeSeconds > MAX_EVIDENCE_VALUE) return null;
  const elapsed = sampledAt -
    new Date(snapshot.nonzeroSinceAt).getTime();
  if (elapsed < 0) return null;
  const samples = snapshot.consecutiveNonzeroSamples;
  if (elapsed < (samples - 1) * 60_000 || elapsed > samples * 60_000) {
    return null;
  }
  const elapsedFullMinutes = Math.floor(elapsed / 60_000);
  return {
    backlogBytes: snapshot.backlogBytes,
    // One persisted metric proves both a contiguous sample streak and elapsed
    // duration. Fifteen samples without fifteen full minutes remains fourteen.
    consecutiveNonzeroSamples: Math.min(samples, elapsedFullMinutes),
    depth: snapshot.backlogCount,
    oldestMessageAgeSeconds,
  };
}

function metricsForObservation(
  observation: AlertRuleObservation,
  knownQueue: KnownQueueSnapshot | null,
): Windowed<MetricBag> {
  switch (observation.ruleId) {
    case "pgid.registration.rate_limited.v1":
    case "pgid.registration.denied.v1":
    case "pgid.registration.restricted_created.v1":
    case "pgid.admin.directory_volume.v1":
      return {
        "5m": countBag(observation.windows["5m"]),
        "15m": countBag(observation.windows["15m"]),
        "60m": countBag(observation.windows["60m"]),
      };
    case "pgid.registration.challenge_unavailable.v1":
    case "pgid.recovery.passkey_failure.v1":
    case "pgid.passkey.step_up_failure.v1":
      return {
        "5m": ratioBag(observation.windows["5m"]),
        "15m": ratioBag(observation.windows["15m"]),
        "60m": ratioBag(observation.windows["60m"]),
      };
    case "pgid.restricted.sensitive_denied.v1":
      return observation.windows;
    case "pgid.oauth.client_report.v1": {
      const mapped = {} as Record<AlertWindowKey, MetricBag>;
      for (const window of ALERT_WINDOW_KEYS) {
        const metrics = observation.windows[window];
        mapped[window] = {
          count: metrics.count,
          ...(metrics.distinctReporters === null
            ? {}
            : { distinctReporters: metrics.distinctReporters }),
          highRiskCount: metrics.highRiskCount,
        };
      }
      return mapped;
    }
    case "pgid.recovery.entry_abuse.v1": {
      const mapped = {} as Record<AlertWindowKey, MetricBag>;
      for (const window of ALERT_WINDOW_KEYS) {
        const metrics = observation.windows[window];
        mapped[window] = {
          denominator: metrics.denied + metrics.started,
          numerator: metrics.denied,
          rateLimited: metrics.rateLimited,
        };
      }
      return mapped;
    }
    case "pgid.admin.sensitive_activity.v1": {
      const mapped = {} as Record<AlertWindowKey, MetricBag>;
      for (const window of ALERT_WINDOW_KEYS) {
        const metrics = observation.windows[window];
        mapped[window] = {
          count: metrics.successes + metrics.protectedDenials,
          protectedDenials: metrics.protectedDenials,
          successes: metrics.successes,
        };
      }
      return mapped;
    }
    case "pgid.security.fanout_gap.v1":
      return {
        "5m": {
          missingOlderThan5mCount: observation.snapshot.missingOlderThan5mCount,
        },
        "15m": {
          missingOlderThan15mCount: observation.snapshot.missingOlderThan15mCount,
        },
        "60m": {
          missingOlderThan5mCount: observation.snapshot.missingOlderThan5mCount,
        },
      };
    case "pgid.logout.delivery_health.v1": {
      const mapped = {} as Record<AlertWindowKey, MetricBag>;
      for (const window of ALERT_WINDOW_KEYS) {
        const metrics = observation.windows[window];
        mapped[window] = {
          dead: observation.current.currentDead,
          denominator: metrics.eligible,
          leaseExpired: metrics.leaseExpired,
          numerator: metrics.unresolved,
          oldestUnresolvedAgeSeconds:
            observation.current.oldestUnresolvedAgeSeconds ?? 0,
        };
      }
      return mapped;
    }
    case "pgid.alert.runtime_health.v1": {
      const snapshot = observation.snapshot;
      const bag: MetricBag = {
        deadOutbox: snapshot.deadOutbox,
        evaluatorAgeSeconds: snapshot.evaluatorAgeSeconds ?? 0,
        evaluatorMissing: snapshot.evaluatorAgeSeconds === null ? 1 : 0,
        outboxDueAgeSeconds: snapshot.outboxDueAgeSeconds ?? 0,
      };
      return { "5m": bag, "15m": bag, "60m": bag };
    }
    case "pgid.queue.dlq_approximate.v1": {
      if (knownQueue === null) return { "5m": {}, "15m": {}, "60m": {} };
      const bag: MetricBag = {
        consecutiveNonzeroSamples: knownQueue.consecutiveNonzeroSamples,
        depth: knownQueue.depth,
      };
      return { "5m": bag, "15m": bag, "60m": bag };
    }
  }
}

const METRIC_NAMES: Readonly<Record<InternalMetricName, AlertMetricName>> = {
  consecutiveNonzeroSamples: "consecutive_nonzero_samples",
  count: "count",
  dead: "dead",
  deadOutbox: "dead_outbox",
  denominator: "count",
  depth: "depth",
  distinctReporters: "distinct_reporters",
  evaluatorAgeSeconds: "evaluator_age_seconds",
  evaluatorMissing: "evaluator_missing",
  highRiskCount: "high_risk_count",
  knownSurfaces: "known_surfaces",
  leaseExpired: "lease_expired",
  missingOlderThan15mCount: "missing",
  missingOlderThan5mCount: "missing",
  numerator: "count",
  oldestUnresolvedAgeSeconds: "oldest_unresolved_age_seconds",
  outboxDueAgeSeconds: "outbox_due_age_seconds",
  protectedDenials: "protected_denials",
  rateLimited: "rate_limited",
  successes: "successes",
};

function evidenceDomain(metric: InternalMetricName): {
  kind: Exclude<AlertEvidenceMetricKind, "ratio">;
  unit: Exclude<AlertEvidenceUnit, "basis_points">;
} {
  if (
    metric === "evaluatorAgeSeconds" ||
    metric === "oldestUnresolvedAgeSeconds" ||
    metric === "outboxDueAgeSeconds"
  ) {
    return { kind: "age_seconds", unit: "seconds" };
  }
  if (metric === "consecutiveNonzeroSamples") {
    return { kind: "consecutive", unit: "samples" };
  }
  if (metric === "evaluatorMissing") {
    return { kind: "boolean", unit: "state" };
  }
  return { kind: "count", unit: "events" };
}

function scalarEvidence(
  metric: InternalMetricName,
  observedValue: number,
  threshold: number,
): AlertMetricEvidence {
  const domain = evidenceDomain(metric);
  return {
    kind: domain.kind,
    metricName: METRIC_NAMES[metric],
    minimumNumeratorCount: null,
    minimumSampleCount: 0,
    observedDenominator: null,
    observedNumerator: null,
    observedValue,
    threshold,
    unit: domain.unit,
  };
}

type ExpressionEvaluation =
  | { components: readonly AlertMetricEvidence[]; status: "breached" }
  | { status: "clear" }
  | { status: "unknown" };

function evaluateExpression(
  expression: ThresholdExpression,
  metrics: MetricBag,
): ExpressionEvaluation {
  if (expression.op === "gte") {
    const observed = metrics[expression.metric];
    if (observed === undefined) return { status: "unknown" };
    return observed < expression.value
      ? { status: "clear" }
      : {
          components: [scalarEvidence(expression.metric, observed, expression.value)],
          status: "breached",
        };
  }
  if (expression.op === "ratio_gte") {
    const numerator = metrics.numerator;
    const denominator = metrics.denominator;
    if (numerator === undefined || denominator === undefined) {
      return { status: "unknown" };
    }
    if (
      numerator < expression.minNumerator ||
      denominator < expression.minDenominator ||
      denominator === 0 ||
      BigInt(numerator) * 10_000n <
        BigInt(denominator) * BigInt(expression.basisPoints)
    ) {
      return { status: "clear" };
    }
    return {
      components: [{
        kind: "ratio",
        metricName: "ratio",
        minimumNumeratorCount: expression.minNumerator,
        minimumSampleCount: expression.minDenominator,
        observedDenominator: denominator,
        observedNumerator: numerator,
        observedValue: Number(
          (BigInt(numerator) * 10_000n) / BigInt(denominator),
        ),
        threshold: expression.basisPoints,
        unit: "basis_points",
      }],
      status: "breached",
    };
  }
  if (expression.op === "all") {
    const components: AlertMetricEvidence[] = [];
    let unknown = false;
    for (const clause of expression.clauses) {
      const result = evaluateExpression(clause, metrics);
      if (result.status === "clear") return result;
      if (result.status === "unknown") unknown = true;
      else components.push(...result.components);
    }
    if (unknown) return { status: "unknown" };
    if (components.length > 2) {
      throw new Error("alert v1 evidence exceeds its two-component schema");
    }
    return { components, status: "breached" };
  }
  let unknown = false;
  for (const clause of expression.clauses) {
    const result = evaluateExpression(clause, metrics);
    if (result.status === "breached") return result;
    if (result.status === "unknown") unknown = true;
  }
  return { status: unknown ? "unknown" : "clear" };
}

interface WindowThresholdEvaluation {
  matches: readonly {
    components: readonly AlertMetricEvidence[];
    window: AlertWindowKey;
  }[];
  unknown: boolean;
}

function evaluateWindowThresholds(
  definition: AlertRuleDefinition,
  metrics: Windowed<MetricBag>,
  severity: "critical" | "warning",
): WindowThresholdEvaluation {
  const matches: {
    components: readonly AlertMetricEvidence[];
    window: AlertWindowKey;
  }[] = [];
  let unknown = false;
  for (const window of ALERT_EVIDENCE_WINDOW_ORDER) {
    const threshold = definition.thresholds[window][severity];
    if (threshold === null) continue;
    const result = evaluateExpression(threshold, metrics[window]);
    if (result.status === "breached") {
      matches.push({ components: result.components, window });
    } else if (result.status === "unknown") {
      unknown = true;
    }
  }
  return { matches, unknown };
}

function selectedEvidence(
  components: readonly AlertMetricEvidence[],
  severity: Exclude<AlertSeverity, "none">,
  window: AlertWindowKey,
): AlertSelectedEvidence {
  const primary = components[0];
  if (!primary || components.length > 2) {
    throw new Error("alert evidence must contain one or two components");
  }
  return {
    ...primary,
    secondary: components[1] ?? null,
    severity,
    windowSeconds: ALERT_WINDOW_SECONDS[window] as 300 | 900 | 3_600,
  };
}

function isImmediateCriticalEvidence(
  ruleId: AlertRuleId,
  evidence: readonly AlertMetricEvidence[],
): boolean {
  const metricName = evidence[0]?.metricName;
  return ruleId === "pgid.logout.delivery_health.v1"
    ? metricName === "dead"
    : ruleId === "pgid.alert.runtime_health.v1" &&
      (metricName === "evaluator_missing" || metricName === "dead_outbox");
}

export function evaluateAlertRule(value: unknown): AlertRuleEvaluation {
  const observation = parseAlertObservation(value);
  alertWindowsAt(observation.asOf);
  const queueSnapshot = observation.ruleId === "pgid.queue.dlq_approximate.v1"
    ? knownQueueSnapshot(observation.snapshot, observation.asOf)
    : null;
  if (
    observation.ruleId === "pgid.queue.dlq_approximate.v1" &&
    queueSnapshot === null
  ) {
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
  const metrics = metricsForObservation(observation, queueSnapshot);
  const definition = ALERT_RULE_DEFINITIONS[observation.ruleId];
  const critical = evaluateWindowThresholds(definition, metrics, "critical");
  const criticalMatches = critical.matches;
  if (criticalMatches.length > 0) {
    const immediate = criticalMatches.find(({ components }) =>
      isImmediateCriticalEvidence(observation.ruleId, components)
    );
    const selected = immediate ?? criticalMatches[0];
    return {
      asOf: observation.asOf,
      breachedWindows: criticalMatches.map(({ window }) => window),
      dimension: observation.dimension,
      evidence: "known",
      immediateCritical: immediate !== undefined,
      ruleId: observation.ruleId,
      selectedEvidence: selectedEvidence(
        selected.components,
        "critical",
        selected.window,
      ),
      severity: "critical",
    };
  }
  const warning = evaluateWindowThresholds(definition, metrics, "warning");
  const warningMatches = warning.matches;
  const selected = warningMatches[0];
  const unknown = selected === undefined && (critical.unknown || warning.unknown);
  return {
    asOf: observation.asOf,
    breachedWindows: warningMatches.map(({ window }) => window),
    dimension: observation.dimension,
    evidence: unknown ? "unknown" : "known",
    immediateCritical: false,
    ruleId: observation.ruleId,
    selectedEvidence: selected
      ? selectedEvidence(selected.components, "warning", selected.window)
      : null,
    severity: selected ? "warning" : "none",
  };
}

export function definitionForAlertRule(
  ruleId: AlertRuleId,
): AlertRuleDefinition {
  return ALERT_RULE_DEFINITIONS[ruleId];
}
