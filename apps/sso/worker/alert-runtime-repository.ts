import {
  ALERT_RUNTIME_SOURCE_QUERY,
  parseAlertRuntimeSourceCompleteness,
  type AlertRuntimeThresholdInput,
} from "./alert-rules";

const EVALUATOR_COMPONENT = "evaluator";
const MAX_GENERATION = 1_000_000;
const MAX_REVISION = 1_000_000_000;
const MAX_LEASE_SECONDS = 300;

export type AlertEvaluatorFailureStatus =
  | "degraded"
  | "failing"
  | "unavailable";

export type AlertEvaluatorErrorCode =
  | "evaluator_failed"
  | "metrics_unavailable"
  | "source_incomplete"
  | "unknown";

export interface AlertEvaluatorLease {
  component: "evaluator";
  generation: number;
  leaseExpiresAt: string;
  leaseId: string;
  revision: number;
  startedAt: string;
  updatedAt: string;
}

export interface InitializeAlertEvaluatorInput {
  initializedAt: string;
}

export interface AcquireAlertEvaluatorLeaseInput {
  leaseDurationSeconds: number;
  startedAt: string;
}

export interface RenewAlertEvaluatorLeaseInput {
  leaseDurationSeconds: number;
  renewedAt: string;
}

export interface RecordAlertEvaluatorSuccessInput {
  completedAt: string;
  watermarkAt: string;
}

export interface RecordAlertEvaluatorFailureInput {
  completedAt: string;
  errorCode: AlertEvaluatorErrorCode;
  status: AlertEvaluatorFailureStatus;
}

export interface AlertEvaluatorSuccessResult {
  bootstrapCreated: boolean;
  committed: boolean;
}

export type AlertRuntimeRepositoryErrorCode =
  | "invalid_input"
  | "source_invalid"
  | "source_unavailable"
  | "write_failed";

export class AlertRuntimeRepositoryError extends Error {
  readonly code: AlertRuntimeRepositoryErrorCode;

  constructor(code: AlertRuntimeRepositoryErrorCode) {
    super(`Alert runtime repository failed (${code})`);
    this.name = "AlertRuntimeRepositoryError";
    this.code = code;
  }
}

type UnknownRecord = Record<string, unknown>;

interface LeaseProjection {
  component: string;
  generation: number;
  lease_expires_at: string;
  lease_id: string;
  revision: number;
  started_at: string;
  updated_at: string;
}

interface RuntimeSourceProjection {
  bootstrap_component: string | null;
  first_success_at: string | null;
  runtime_component: string | null;
  runtime_generation: number | null;
  runtime_last_error_at: string | null;
  runtime_last_error_code: string | null;
  runtime_last_started_at: string | null;
  runtime_last_success_at: string | null;
  runtime_revision: number | null;
  runtime_status: string | null;
  runtime_updated_at: string | null;
  source_generation: number | null;
  source_revision: number | null;
}

const LEASE_PROJECTION_KEYS = [
  "component",
  "generation",
  "lease_expires_at",
  "lease_id",
  "revision",
  "started_at",
  "updated_at",
] as const;

const FAILURE_STATUSES = new Set<string>([
  "degraded",
  "failing",
  "unavailable",
]);

const ERROR_CODES = new Set<string>([
  "evaluator_failed",
  "metrics_unavailable",
  "source_incomplete",
  "unknown",
]);

function fail(code: AlertRuntimeRepositoryErrorCode): never {
  throw new AlertRuntimeRepositoryError(code);
}

function isRepositoryErrorCode(
  value: unknown,
): value is AlertRuntimeRepositoryErrorCode {
  return (
    value === "invalid_input" ||
    value === "source_invalid" ||
    value === "source_unavailable" ||
    value === "write_failed"
  );
}

function exactLocalRepositoryErrorCode(
  error: unknown,
): AlertRuntimeRepositoryErrorCode | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  try {
    if (Object.getPrototypeOf(error) !== AlertRuntimeRepositoryError.prototype) {
      return undefined;
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, "code");
    if (
      !descriptor ||
      !("value" in descriptor) ||
      !isRepositoryErrorCode(descriptor.value)
    ) {
      return undefined;
    }
    return descriptor.value;
  } catch {
    return undefined;
  }
}

function redactedRepositoryError(
  error: unknown,
  fallback: AlertRuntimeRepositoryErrorCode,
): AlertRuntimeRepositoryError {
  return new AlertRuntimeRepositoryError(
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

function canonicalTimestamp(value: unknown): { iso: string; time: number } {
  if (typeof value !== "string") fail("invalid_input");
  const time = new Date(value).getTime();
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) {
    fail("invalid_input");
  }
  return { iso: value, time };
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

function isFailureStatus(
  value: unknown,
): value is AlertEvaluatorFailureStatus {
  return typeof value === "string" && FAILURE_STATUSES.has(value);
}

function isErrorCode(value: unknown): value is AlertEvaluatorErrorCode {
  return typeof value === "string" && ERROR_CODES.has(value);
}

function parseLease(value: unknown): AlertEvaluatorLease {
  const record = exactRecord(value, [
    "component",
    "generation",
    "leaseExpiresAt",
    "leaseId",
    "revision",
    "startedAt",
    "updatedAt",
  ]);
  if (record.component !== EVALUATOR_COMPONENT) fail("invalid_input");
  if (
    typeof record.leaseId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      record.leaseId,
    )
  ) {
    fail("invalid_input");
  }
  const generation = boundedInteger(record.generation, 1, MAX_GENERATION);
  const revision = boundedInteger(record.revision, 1, MAX_REVISION);
  const startedAt = canonicalTimestamp(record.startedAt);
  const updatedAt = canonicalTimestamp(record.updatedAt);
  const leaseExpiresAt = canonicalTimestamp(record.leaseExpiresAt);
  if (
    updatedAt.time < startedAt.time ||
    leaseExpiresAt.time <= updatedAt.time ||
    leaseExpiresAt.time - updatedAt.time > MAX_LEASE_SECONDS * 1_000
  ) {
    fail("invalid_input");
  }
  return {
    component: EVALUATOR_COMPONENT,
    generation,
    leaseExpiresAt: leaseExpiresAt.iso,
    leaseId: record.leaseId,
    revision,
    startedAt: startedAt.iso,
    updatedAt: updatedAt.iso,
  };
}

function parseLeaseProjection(value: unknown): AlertEvaluatorLease {
  const record = exactRecord(value, LEASE_PROJECTION_KEYS);
  return parseLease({
    component: record.component,
    generation: record.generation,
    leaseExpiresAt: record.lease_expires_at,
    leaseId: record.lease_id,
    revision: record.revision,
    startedAt: record.started_at,
    updatedAt: record.updated_at,
  });
}

function leaseExpiry(updatedAt: number, durationSeconds: number): string {
  return new Date(updatedAt + durationSeconds * 1_000).toISOString();
}

const LEASE_RETURNING = `RETURNING
  component AS component,
  generation AS generation,
  lease_expires_at AS lease_expires_at,
  lease_id AS lease_id,
  revision AS revision,
  last_started_at AS started_at,
  updated_at AS updated_at`;

export async function initializeAlertEvaluatorRuntime(
  database: D1Database,
  input: InitializeAlertEvaluatorInput,
): Promise<boolean> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const record = exactRecord(input, ["initializedAt"]);
    const initializedAt = canonicalTimestamp(record.initializedAt).iso;
    const result = await database.prepare(
      `INSERT INTO alert_runtime_status (component, updated_at)
       SELECT ?, ?
        WHERE NOT EXISTS (
          SELECT 1 FROM alert_runtime_status WHERE component = ?
        )`,
    )
      .bind(EVALUATOR_COMPONENT, initializedAt, EVALUATOR_COMPONENT)
      .run();
    if (result.meta.changes !== 0 && result.meta.changes !== 1) {
      fail("write_failed");
    }
    return result.meta.changes === 1;
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}

export async function acquireAlertEvaluatorLease(
  database: D1Database,
  input: AcquireAlertEvaluatorLeaseInput,
): Promise<AlertEvaluatorLease | null> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const record = exactRecord(input, ["leaseDurationSeconds", "startedAt"]);
    const startedAt = canonicalTimestamp(record.startedAt);
    const durationSeconds = boundedInteger(
      record.leaseDurationSeconds,
      1,
      MAX_LEASE_SECONDS,
    );
    const leaseId = crypto.randomUUID();
    const expiresAt = leaseExpiry(startedAt.time, durationSeconds);
    const row = await database.prepare(
      `UPDATE alert_runtime_status
          SET generation = generation + 1,
              revision = revision + 1,
              lease_id = ?,
              lease_expires_at = ?,
              last_started_at = ?,
              updated_at = ?
        WHERE component = ?
          AND generation < ?
          AND revision < ?
          AND unixepoch(updated_at) < unixepoch(?)
          AND (
            lease_id IS NULL
            OR unixepoch(lease_expires_at) <= unixepoch(?)
          )
        ${LEASE_RETURNING}`,
    )
      .bind(
        leaseId,
        expiresAt,
        startedAt.iso,
        startedAt.iso,
        EVALUATOR_COMPONENT,
        MAX_GENERATION,
        MAX_REVISION,
        startedAt.iso,
        startedAt.iso,
      )
      .first<LeaseProjection>();
    return row === null ? null : parseLeaseProjection(row);
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}

export async function renewAlertEvaluatorLease(
  database: D1Database,
  lease: AlertEvaluatorLease,
  input: RenewAlertEvaluatorLeaseInput,
): Promise<AlertEvaluatorLease | null> {
  try {
    if (arguments.length !== 3) fail("invalid_input");
    const current = parseLease(lease);
    const record = exactRecord(input, ["leaseDurationSeconds", "renewedAt"]);
    const renewedAt = canonicalTimestamp(record.renewedAt);
    const durationSeconds = boundedInteger(
      record.leaseDurationSeconds,
      1,
      MAX_LEASE_SECONDS,
    );
    const expiresAt = leaseExpiry(renewedAt.time, durationSeconds);
    if (
      renewedAt.time <= new Date(current.updatedAt).getTime() ||
      renewedAt.time >= new Date(current.leaseExpiresAt).getTime() ||
      new Date(expiresAt).getTime() < new Date(current.leaseExpiresAt).getTime() ||
      current.revision >= MAX_REVISION
    ) {
      fail("invalid_input");
    }
    const row = await database.prepare(
      `UPDATE alert_runtime_status
          SET revision = revision + 1,
              lease_expires_at = ?,
              updated_at = ?
        WHERE component = ?
          AND generation = ?
          AND revision = ?
          AND lease_id = ?
          AND lease_expires_at = ?
          AND last_started_at = ?
          AND updated_at = ?
        ${LEASE_RETURNING}`,
    )
      .bind(
        expiresAt,
        renewedAt.iso,
        EVALUATOR_COMPONENT,
        current.generation,
        current.revision,
        current.leaseId,
        current.leaseExpiresAt,
        current.startedAt,
        current.updatedAt,
      )
      .first<LeaseProjection>();
    return row === null ? null : parseLeaseProjection(row);
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}

export async function recordAlertEvaluatorSuccess(
  database: D1Database,
  lease: AlertEvaluatorLease,
  input: RecordAlertEvaluatorSuccessInput,
): Promise<AlertEvaluatorSuccessResult> {
  try {
    if (arguments.length !== 3) fail("invalid_input");
    const current = parseLease(lease);
    const record = exactRecord(input, ["completedAt", "watermarkAt"]);
    const completedAt = canonicalTimestamp(record.completedAt);
    const watermarkAt = canonicalTimestamp(record.watermarkAt);
    if (
      completedAt.time <= new Date(current.updatedAt).getTime() ||
      completedAt.time >= new Date(current.leaseExpiresAt).getTime() ||
      watermarkAt.time > completedAt.time ||
      current.revision >= MAX_REVISION
    ) {
      fail("invalid_input");
    }
    const nextRevision = current.revision + 1;
    const results = await database.batch([
      database.prepare(
        `UPDATE alert_runtime_status
            SET status = 'healthy',
                revision = ?,
                lease_id = NULL,
                lease_expires_at = NULL,
                last_success_at = ?,
                watermark_at = ?,
                updated_at = ?
          WHERE component = ?
            AND generation = ?
            AND revision = ?
            AND lease_id = ?
            AND lease_expires_at = ?
            AND last_started_at = ?
            AND updated_at = ?`,
      ).bind(
        nextRevision,
        completedAt.iso,
        watermarkAt.iso,
        completedAt.iso,
        EVALUATOR_COMPONENT,
        current.generation,
        current.revision,
        current.leaseId,
        current.leaseExpiresAt,
        current.startedAt,
        current.updatedAt,
      ),
      database.prepare(
        `INSERT INTO alert_evaluator_bootstrap
          (component, first_success_at, source_generation, source_revision)
         SELECT component, last_success_at, generation, revision
           FROM alert_runtime_status
          WHERE component = ?
            AND status = 'healthy'
            AND generation = ?
            AND revision = ?
            AND lease_id IS NULL
            AND last_started_at = ?
            AND last_success_at = ?
            AND watermark_at = ?
            AND NOT EXISTS (SELECT 1 FROM alert_evaluator_bootstrap)`,
      ).bind(
        EVALUATOR_COMPONENT,
        current.generation,
        nextRevision,
        current.startedAt,
        completedAt.iso,
        watermarkAt.iso,
      ),
    ]);
    const updated = results[0]?.meta.changes ?? -1;
    const bootstrapCreated = results[1]?.meta.changes ?? -1;
    if (
      (updated !== 0 && updated !== 1) ||
      (bootstrapCreated !== 0 && bootstrapCreated !== 1) ||
      (updated === 0 && bootstrapCreated !== 0)
    ) {
      fail("write_failed");
    }
    return {
      bootstrapCreated: bootstrapCreated === 1,
      committed: updated === 1,
    };
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}

export async function recordAlertEvaluatorFailure(
  database: D1Database,
  lease: AlertEvaluatorLease,
  input: RecordAlertEvaluatorFailureInput,
): Promise<boolean> {
  try {
    if (arguments.length !== 3) fail("invalid_input");
    const current = parseLease(lease);
    const record = exactRecord(input, ["completedAt", "errorCode", "status"]);
    const completedAt = canonicalTimestamp(record.completedAt);
    if (
      !isFailureStatus(record.status) ||
      !isErrorCode(record.errorCode) ||
      completedAt.time <= new Date(current.updatedAt).getTime() ||
      completedAt.time >= new Date(current.leaseExpiresAt).getTime() ||
      current.revision >= MAX_REVISION
    ) {
      fail("invalid_input");
    }
    const result = await database.prepare(
      `UPDATE alert_runtime_status
          SET status = ?,
              revision = revision + 1,
              lease_id = NULL,
              lease_expires_at = NULL,
              last_error_at = ?,
              last_error_code = ?,
              updated_at = ?
        WHERE component = ?
          AND generation = ?
          AND revision = ?
          AND lease_id = ?
          AND lease_expires_at = ?
          AND last_started_at = ?
          AND updated_at = ?`,
    )
      .bind(
        record.status,
        completedAt.iso,
        record.errorCode,
        completedAt.iso,
        EVALUATOR_COMPONENT,
        current.generation,
        current.revision,
        current.leaseId,
        current.leaseExpiresAt,
        current.startedAt,
        current.updatedAt,
      )
      .run();
    if (result.meta.changes !== 0 && result.meta.changes !== 1) {
      fail("write_failed");
    }
    return result.meta.changes === 1;
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}

export async function readAlertRuntimeThresholdInput(
  database: D1Database,
  asOf: string,
): Promise<AlertRuntimeThresholdInput | null> {
  if (arguments.length !== 2) fail("invalid_input");
  const canonicalAsOf = canonicalTimestamp(asOf).iso;
  let projection: RuntimeSourceProjection | null;
  try {
    projection = await database.prepare(ALERT_RUNTIME_SOURCE_QUERY)
      .first<RuntimeSourceProjection>();
  } catch (error) {
    throw redactedRepositoryError(error, "source_unavailable");
  }
  if (projection === null) fail("source_invalid");
  try {
    return parseAlertRuntimeSourceCompleteness(projection, canonicalAsOf);
  } catch (error) {
    throw redactedRepositoryError(error, "source_invalid");
  }
}
