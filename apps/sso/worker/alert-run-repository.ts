import {
  ALERT_EVALUATOR_SOURCE_IDS,
  alertEvaluatorDecisionManifestDigest,
  alertEvaluatorSourceManifestDigest,
  parseAlertEvaluatorDecisionProofValue,
  parseAlertEvaluatorDigest,
  parseAlertEvaluatorSourceId,
  parseAlertEvaluatorSourceProofValue,
  type AlertEvaluatorDecisionProofValue,
  type AlertEvaluatorSourceId,
  type AlertEvaluatorSourceProofValue,
  type AlertEvaluatorSourceStatus,
} from "./alert-run-proof";
import {
  ALERT_RUNTIME_GENERATION_MAX,
  ALERT_RUNTIME_REVISION_MAX,
} from "./alert-rules";

const COMPONENT = "evaluator";
const TRIGGER_CRON = "* * * * *";
const MAX_ACTIVE_REVISION = ALERT_RUNTIME_REVISION_MAX - 1;
const MAX_LEASE_SECONDS = 300;

export type AlertEvaluatorRunStatus =
  | "abandoned"
  | "failed"
  | "running"
  | "sealed"
  | "succeeded";
export type AlertEvaluatorRunFailureStatus =
  | "degraded"
  | "failing"
  | "unavailable";
export type AlertEvaluatorRunErrorCode =
  | "evaluator_failed"
  | "metrics_unavailable"
  | "source_incomplete"
  | "unknown";

export interface AlertEvaluatorRunFence {
  leaseExpiresAt: string;
  leaseId: string;
  leaseRevision: number;
  leaseUpdatedAt: string;
  runId: string;
  runtimeGeneration: number;
  startedAt: string;
}

export interface AlertEvaluatorRun {
  acquiredRevision: number;
  asOf: string | null;
  completedAt: string | null;
  createdAt: string;
  decisionCount: number | null;
  decisionManifestSha256: string | null;
  failureErrorCode: AlertEvaluatorRunErrorCode | null;
  failureStatus: AlertEvaluatorRunFailureStatus | null;
  id: string;
  leaseExpiresAt: string;
  leaseId: string;
  leaseRevision: number;
  leaseUpdatedAt: string;
  partialSourceCount: number | null;
  runtimeGeneration: number;
  sourceCount: number | null;
  sourceManifestSha256: string | null;
  startedAt: string;
  status: AlertEvaluatorRunStatus;
  terminalRuntimeRevision: number | null;
  triggerCron: typeof TRIGGER_CRON;
  triggerScheduledAt: string;
  updatedAt: string;
  watermarkAt: string | null;
}

export interface AlertEvaluatorDecisionProof {
  asOf: string;
  decisionSha256: string;
  disposition: AlertEvaluatorDecisionProofValue["disposition"];
  evaluationSha256: string;
  identitySha256: string;
  ordinal: number;
  recordedAt: string;
  runId: string;
  runtimeGeneration: number;
  runtimeRevision: number;
  sourceId: AlertEvaluatorSourceId;
  stateGeneration: number | null;
  stateId: string | null;
  stateRevision: number | null;
}

export interface AcquireAlertEvaluatorRunInput {
  leaseDurationSeconds: number;
  scheduledAt: string;
  startedAt: string;
  triggerCron: typeof TRIGGER_CRON;
}

export type AcquireAlertEvaluatorRunResult =
  | { fence: AlertEvaluatorRunFence; kind: "acquired"; run: AlertEvaluatorRun }
  | { kind: "duplicate"; run: AlertEvaluatorRun }
  | null;

export interface RenewAlertEvaluatorRunInput {
  leaseDurationSeconds: number;
  renewedAt: string;
}

export type AlertEvaluatorRunMutationResult =
  | { fence: AlertEvaluatorRunFence; kind: "committed"; run: AlertEvaluatorRun }
  | { fence: AlertEvaluatorRunFence; kind: "replayed"; run: AlertEvaluatorRun }
  | { kind: "lost" };

export interface BindAlertEvaluatorRunAsOfInput {
  asOf: string;
  boundAt: string;
}

export interface RecordAlertEvaluatorRunSourceInput {
  asOf: string;
  proof: AlertEvaluatorSourceProofValue;
  recordedAt: string;
}

export type AlertEvaluatorProofWriteResult = "recorded" | "replayed" | "lost";

export interface SealAlertEvaluatorRunInput {
  decisions: readonly AlertEvaluatorDecisionProofValue[];
  sealedAt: string;
}

export interface RecordSuppressedAlertEvaluatorDecisionInput {
  asOf: string;
  proof: AlertEvaluatorDecisionProofValue & {
    disposition: "suppressed_partial";
  };
  recordedAt: string;
}

export interface RecordNoStateChangeAlertEvaluatorDecisionInput {
  absence: AlertEvaluatorNoStateAbsence;
  asOf: string;
  proof: AlertEvaluatorDecisionProofValue & {
    disposition: "no_state_change";
  };
  recordedAt: string;
}

export interface AlertEvaluatorNoStateAbsence {
  environment: "local" | "preview" | "production";
  queueName: string | null;
  ruleId: string;
  sourceKind: "d1_exact" | "queue_approximate";
  subjectRef: string | null;
}

export interface RecordAlertEvaluatorRunSuccessInput {
  completedAt: string;
}

export interface RecordAlertEvaluatorRunFailureInput {
  completedAt: string;
  errorCode: AlertEvaluatorRunErrorCode;
  status: AlertEvaluatorRunFailureStatus;
}

export type AlertEvaluatorTerminalResult =
  | { bootstrapCreated: boolean; kind: "committed"; run: AlertEvaluatorRun }
  | { bootstrapCreated: boolean; kind: "replayed"; run: AlertEvaluatorRun }
  | { kind: "lost" };

export type AlertRunRepositoryErrorCode =
  | "conflict"
  | "counter_exhausted"
  | "invalid_input"
  | "source_invalid"
  | "source_unavailable"
  | "write_failed";

export class AlertRunRepositoryError extends Error {
  readonly code: AlertRunRepositoryErrorCode;

  constructor(code: AlertRunRepositoryErrorCode) {
    super(`Alert run repository failed (${code})`);
    this.name = "AlertRunRepositoryError";
    this.code = code;
  }
}

type UnknownRecord = Record<string, unknown>;

interface RuntimeProjection {
  generation: number;
  last_error_at: string | null;
  last_error_code: string | null;
  last_started_at: string | null;
  last_success_at: string | null;
  lease_expires_at: string | null;
  lease_id: string | null;
  revision: number;
  status: string;
  updated_at: string;
  watermark_at: string | null;
}

interface SourceProjection {
  as_of: string;
  incomplete_count: number;
  observation_count: number;
  proof_sha256: string;
  recorded_at: string;
  run_id: string;
  runtime_generation: number;
  runtime_revision: number;
  source_id: string;
  status: string;
}

interface DecisionProjection {
  as_of: string;
  decision_sha256: string;
  disposition: string;
  evaluation_sha256: string;
  identity_sha256: string;
  ordinal: number;
  recorded_at: string;
  run_id: string;
  runtime_generation: number;
  runtime_revision: number;
  source_id: string;
  state_generation: number | null;
  state_id: string | null;
  state_revision: number | null;
}

const RUN_PROJECTION = `
  id, trigger_cron, trigger_scheduled_at, runtime_generation,
  acquired_revision, lease_revision, lease_id, started_at, lease_updated_at,
  lease_expires_at, as_of, source_count, partial_source_count,
  source_manifest_sha256, decision_count, decision_manifest_sha256, status,
  completed_at, watermark_at, terminal_runtime_revision, failure_status,
  failure_error_code, created_at, updated_at`;

const SOURCE_PROJECTION = `
  run_id, source_id, as_of, status, observation_count, incomplete_count,
  proof_sha256, runtime_generation, runtime_revision, recorded_at`;

const DECISION_PROJECTION = `
  run_id, source_id, ordinal, identity_sha256, evaluation_sha256,
  decision_sha256, disposition, as_of, state_id, state_generation,
  state_revision, runtime_generation, runtime_revision, recorded_at`;

function fail(code: AlertRunRepositoryErrorCode): never {
  throw new AlertRunRepositoryError(code);
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
  if (
    value.length !== 24 ||
    !Number.isFinite(time) ||
    new Date(time).toISOString() !== value
  ) {
    fail("invalid_input");
  }
  return { iso: value, time };
}

function sourceTimestamp(value: unknown): string {
  try {
    return canonicalTimestamp(value).iso;
  } catch {
    fail("source_invalid");
  }
}

function boundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  code: AlertRunRepositoryErrorCode = "invalid_input",
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    fail(code);
  }
  return value;
}

function uuidV4(value: unknown, code: AlertRunRepositoryErrorCode): string {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      value,
    )
  ) {
    fail(code);
  }
  return value;
}

function nullableTimestamp(
  value: unknown,
  code: AlertRunRepositoryErrorCode,
): string | null {
  if (value === null) return null;
  try {
    return canonicalTimestamp(value).iso;
  } catch {
    fail(code);
  }
}

function nullableInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): number | null {
  return value === null
    ? null
    : boundedInteger(value, minimum, maximum, "source_invalid");
}

function nullableDigest(value: unknown): string | null {
  if (value === null) return null;
  try {
    return parseAlertEvaluatorDigest(value);
  } catch {
    fail("source_invalid");
  }
}

function runStatus(value: unknown): AlertEvaluatorRunStatus {
  if (
    value !== "running" &&
    value !== "sealed" &&
    value !== "succeeded" &&
    value !== "failed" &&
    value !== "abandoned"
  ) {
    fail("source_invalid");
  }
  return value;
}

function failureStatus(value: unknown): AlertEvaluatorRunFailureStatus | null {
  if (value === null) return null;
  if (value !== "degraded" && value !== "failing" && value !== "unavailable") {
    fail("source_invalid");
  }
  return value;
}

function errorCode(value: unknown): AlertEvaluatorRunErrorCode | null {
  if (value === null) return null;
  if (
    value !== "evaluator_failed" &&
    value !== "metrics_unavailable" &&
    value !== "source_incomplete" &&
    value !== "unknown"
  ) {
    fail("source_invalid");
  }
  return value;
}

function parseRun(value: unknown): AlertEvaluatorRun {
  const record = recordValue(value);
  if (record.trigger_cron !== TRIGGER_CRON) fail("source_invalid");
  return {
    acquiredRevision: boundedInteger(
      record.acquired_revision,
      1,
      MAX_ACTIVE_REVISION,
      "source_invalid",
    ),
    asOf: nullableTimestamp(record.as_of, "source_invalid"),
    completedAt: nullableTimestamp(record.completed_at, "source_invalid"),
    createdAt: sourceTimestamp(record.created_at),
    decisionCount: nullableInteger(record.decision_count, 0, 10_000),
    decisionManifestSha256: nullableDigest(record.decision_manifest_sha256),
    failureErrorCode: errorCode(record.failure_error_code),
    failureStatus: failureStatus(record.failure_status),
    id: uuidV4(record.id, "source_invalid"),
    leaseExpiresAt: sourceTimestamp(record.lease_expires_at),
    leaseId: uuidV4(record.lease_id, "source_invalid"),
    leaseRevision: boundedInteger(
      record.lease_revision,
      1,
      MAX_ACTIVE_REVISION,
      "source_invalid",
    ),
    leaseUpdatedAt: sourceTimestamp(record.lease_updated_at),
    partialSourceCount: nullableInteger(record.partial_source_count, 0, 9),
    runtimeGeneration: boundedInteger(
      record.runtime_generation,
      1,
      ALERT_RUNTIME_GENERATION_MAX,
      "source_invalid",
    ),
    sourceCount: nullableInteger(record.source_count, 9, 9),
    sourceManifestSha256: nullableDigest(record.source_manifest_sha256),
    startedAt: sourceTimestamp(record.started_at),
    status: runStatus(record.status),
    terminalRuntimeRevision: nullableInteger(
      record.terminal_runtime_revision,
      2,
      ALERT_RUNTIME_REVISION_MAX,
    ),
    triggerCron: TRIGGER_CRON,
    triggerScheduledAt: sourceTimestamp(record.trigger_scheduled_at),
    updatedAt: sourceTimestamp(record.updated_at),
    watermarkAt: nullableTimestamp(record.watermark_at, "source_invalid"),
  };
}

function fenceFromRun(run: AlertEvaluatorRun): AlertEvaluatorRunFence {
  return {
    leaseExpiresAt: run.leaseExpiresAt,
    leaseId: run.leaseId,
    leaseRevision: run.leaseRevision,
    leaseUpdatedAt: run.leaseUpdatedAt,
    runId: run.id,
    runtimeGeneration: run.runtimeGeneration,
    startedAt: run.startedAt,
  };
}

function parseFence(value: unknown): AlertEvaluatorRunFence {
  const record = exactRecord(value, [
    "leaseExpiresAt",
    "leaseId",
    "leaseRevision",
    "leaseUpdatedAt",
    "runId",
    "runtimeGeneration",
    "startedAt",
  ]);
  const startedAt = canonicalTimestamp(record.startedAt);
  const leaseUpdatedAt = canonicalTimestamp(record.leaseUpdatedAt);
  const leaseExpiresAt = canonicalTimestamp(record.leaseExpiresAt);
  if (
    leaseUpdatedAt.time < startedAt.time ||
    leaseExpiresAt.time <= leaseUpdatedAt.time ||
    leaseExpiresAt.time - leaseUpdatedAt.time > MAX_LEASE_SECONDS * 1_000
  ) {
    fail("invalid_input");
  }
  return {
    leaseExpiresAt: leaseExpiresAt.iso,
    leaseId: uuidV4(record.leaseId, "invalid_input"),
    leaseRevision: boundedInteger(
      record.leaseRevision,
      1,
      MAX_ACTIVE_REVISION,
    ),
    leaseUpdatedAt: leaseUpdatedAt.iso,
    runId: uuidV4(record.runId, "invalid_input"),
    runtimeGeneration: boundedInteger(
      record.runtimeGeneration,
      1,
      ALERT_RUNTIME_GENERATION_MAX,
    ),
    startedAt: startedAt.iso,
  };
}

export function validateAlertEvaluatorRunFence(
  value: unknown,
): AlertEvaluatorRunFence {
  return parseFence(value);
}

function redacted(error: unknown, fallback: AlertRunRepositoryErrorCode): never {
  if (
    error instanceof AlertRunRepositoryError &&
    Object.getPrototypeOf(error) === AlertRunRepositoryError.prototype
  ) {
    throw new AlertRunRepositoryError(error.code);
  }
  throw new AlertRunRepositoryError(fallback);
}

async function readRunById(
  database: D1Database,
  runId: string,
): Promise<AlertEvaluatorRun | null> {
  let row: unknown;
  try {
    row = await database.prepare(
      `SELECT ${RUN_PROJECTION} FROM alert_evaluator_run WHERE id = ?`,
    ).bind(runId).first();
  } catch (error) {
    redacted(error, "source_unavailable");
  }
  return row === null ? null : parseRun(row);
}

export async function readAlertEvaluatorRun(
  database: D1Database,
  runId: string,
): Promise<AlertEvaluatorRun | null> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    return await readRunById(database, uuidV4(runId, "invalid_input"));
  } catch (error) {
    redacted(error, "source_unavailable");
  }
}

async function readOccurrence(
  database: D1Database,
  scheduledAt: string,
): Promise<AlertEvaluatorRun | null> {
  const row = await database.prepare(
    `SELECT ${RUN_PROJECTION}
       FROM alert_evaluator_run
      WHERE trigger_cron = ? AND trigger_scheduled_at = ?`,
  ).bind(TRIGGER_CRON, scheduledAt).first();
  return row === null ? null : parseRun(row);
}

async function readRuntime(database: D1Database): Promise<RuntimeProjection> {
  const row = await database.prepare(
    `SELECT generation, revision, lease_id, lease_expires_at, last_started_at,
            last_success_at, last_error_at, last_error_code, watermark_at,
            status, updated_at
       FROM alert_runtime_status WHERE component = ?`,
  ).bind(COMPONENT).first<RuntimeProjection>();
  if (row === null) fail("source_invalid");
  boundedInteger(row.generation, 0, ALERT_RUNTIME_GENERATION_MAX, "source_invalid");
  boundedInteger(row.revision, 0, ALERT_RUNTIME_REVISION_MAX, "source_invalid");
  sourceTimestamp(row.updated_at);
  return row;
}

function leaseExpiry(at: number, seconds: number): string {
  return new Date(at + seconds * 1_000).toISOString();
}

function runMatchesFence(run: AlertEvaluatorRun, fence: AlertEvaluatorRunFence): boolean {
  return run.id === fence.runId &&
    run.runtimeGeneration === fence.runtimeGeneration &&
    run.leaseRevision === fence.leaseRevision &&
    run.leaseId === fence.leaseId &&
    run.startedAt === fence.startedAt &&
    run.leaseUpdatedAt === fence.leaseUpdatedAt &&
    run.leaseExpiresAt === fence.leaseExpiresAt;
}

export async function acquireAlertEvaluatorRun(
  database: D1Database,
  input: AcquireAlertEvaluatorRunInput,
): Promise<AcquireAlertEvaluatorRunResult> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const record = exactRecord(input, [
      "leaseDurationSeconds",
      "scheduledAt",
      "startedAt",
      "triggerCron",
    ]);
    if (record.triggerCron !== TRIGGER_CRON) fail("invalid_input");
    const scheduledAt = canonicalTimestamp(record.scheduledAt);
    const startedAt = canonicalTimestamp(record.startedAt);
    const duration = boundedInteger(
      record.leaseDurationSeconds,
      1,
      MAX_LEASE_SECONDS,
    );
    if (scheduledAt.time > startedAt.time) fail("invalid_input");
    const duplicate = await readOccurrence(database, scheduledAt.iso);
    if (duplicate) return { kind: "duplicate", run: duplicate };
    const runtime = await readRuntime(database);
    if (
      runtime.generation >= ALERT_RUNTIME_GENERATION_MAX ||
      runtime.revision >= MAX_ACTIVE_REVISION
    ) {
      fail("counter_exhausted");
    }
    const runtimeUpdated = canonicalTimestamp(runtime.updated_at);
    const runtimeExpiry = runtime.lease_expires_at === null
      ? null
      : canonicalTimestamp(runtime.lease_expires_at);
    if (
      runtimeUpdated.time >= startedAt.time ||
      (runtime.lease_id !== null &&
        runtimeExpiry !== null &&
        runtimeExpiry.time > startedAt.time)
    ) {
      return null;
    }
    const generation = runtime.generation + 1;
    const revision = runtime.revision + 1;
    const runId = crypto.randomUUID();
    const leaseId = crypto.randomUUID();
    const expiresAt = leaseExpiry(startedAt.time, duration);
    const predecessor = runtime.lease_id === null
      ? null
      : await database.prepare(
        `SELECT id FROM alert_evaluator_run
          WHERE component = ? AND runtime_generation = ?
            AND lease_id = ? AND status IN ('running', 'sealed')
            AND lease_expires_at <= ?`,
      ).bind(
        COMPONENT,
        runtime.generation,
        runtime.lease_id,
        startedAt.iso,
      ).first("id");
    let result: D1Result;
    try {
      result = await database.prepare(
        `INSERT INTO alert_evaluator_run
          (id, component, trigger_cron, trigger_scheduled_at,
           runtime_generation, acquired_revision, lease_revision, lease_id,
           started_at, lease_updated_at, lease_expires_at, status,
           created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?)`,
      ).bind(
        runId,
        COMPONENT,
        TRIGGER_CRON,
        scheduledAt.iso,
        generation,
        revision,
        revision,
        leaseId,
        startedAt.iso,
        startedAt.iso,
        expiresAt,
        startedAt.iso,
        startedAt.iso,
      ).run();
    } catch {
      const committed = await readRunById(database, runId);
      if (
        committed && committed.status === "running" &&
        committed.triggerScheduledAt === scheduledAt.iso &&
        committed.runtimeGeneration === generation &&
        committed.acquiredRevision === revision &&
        committed.leaseRevision === revision && committed.leaseId === leaseId &&
        committed.startedAt === startedAt.iso &&
        committed.leaseUpdatedAt === startedAt.iso &&
        committed.leaseExpiresAt === expiresAt
      ) {
        return {
          fence: fenceFromRun(committed),
          kind: "acquired",
          run: committed,
        };
      }
      const raced = await readOccurrence(database, scheduledAt.iso);
      if (raced) return { kind: "duplicate", run: raced };
      const after = await readRuntime(database);
      const unchanged = after.generation === runtime.generation &&
        after.revision === runtime.revision && after.lease_id === runtime.lease_id &&
        after.lease_expires_at === runtime.lease_expires_at &&
        after.updated_at === runtime.updated_at;
      if (unchanged) fail("write_failed");
      const afterExpiry = after.lease_expires_at === null
        ? null
        : canonicalTimestamp(after.lease_expires_at);
      if (
        after.generation > runtime.generation && after.revision > runtime.revision &&
        after.lease_id !== null && afterExpiry !== null &&
        afterExpiry.time > startedAt.time
      ) {
        return null;
      }
      fail("write_failed");
    }
    const expectedChanges = predecessor === null ? 2 : 3;
    if (result.meta.changes !== expectedChanges) fail("write_failed");
    const run = await readRunById(database, runId);
    if (!run || run.status !== "running") fail("write_failed");
    return { fence: fenceFromRun(run), kind: "acquired", run };
  } catch (error) {
    redacted(error, "write_failed");
  }
}

export async function renewAlertEvaluatorRun(
  database: D1Database,
  fenceValue: AlertEvaluatorRunFence,
  input: RenewAlertEvaluatorRunInput,
): Promise<AlertEvaluatorRunMutationResult> {
  try {
    if (arguments.length !== 3) fail("invalid_input");
    const fence = parseFence(fenceValue);
    const record = exactRecord(input, ["leaseDurationSeconds", "renewedAt"]);
    const renewedAt = canonicalTimestamp(record.renewedAt);
    const duration = boundedInteger(
      record.leaseDurationSeconds,
      1,
      MAX_LEASE_SECONDS,
    );
    const currentUpdated = canonicalTimestamp(fence.leaseUpdatedAt);
    const currentExpiry = canonicalTimestamp(fence.leaseExpiresAt);
    const expiresAt = leaseExpiry(renewedAt.time, duration);
    if (
      renewedAt.time <= currentUpdated.time ||
      renewedAt.time >= currentExpiry.time ||
      new Date(expiresAt).getTime() < currentExpiry.time ||
      fence.leaseRevision >= MAX_ACTIVE_REVISION
    ) {
      fail(fence.leaseRevision >= MAX_ACTIVE_REVISION
        ? "counter_exhausted"
        : "invalid_input");
    }
    const nextRevision = fence.leaseRevision + 1;
    let result: D1Result | null = null;
    try {
      result = await database.prepare(
        `UPDATE alert_evaluator_run
          SET lease_revision = ?, lease_updated_at = ?, lease_expires_at = ?,
              updated_at = ?
        WHERE id = ? AND runtime_generation = ? AND lease_revision = ?
          AND lease_id = ? AND started_at = ? AND lease_updated_at = ?
          AND lease_expires_at = ? AND status IN ('running', 'sealed')`,
      ).bind(
        nextRevision,
        renewedAt.iso,
        expiresAt,
        renewedAt.iso,
        fence.runId,
        fence.runtimeGeneration,
        fence.leaseRevision,
        fence.leaseId,
        fence.startedAt,
        fence.leaseUpdatedAt,
        fence.leaseExpiresAt,
      ).run();
    } catch {
      // Exact readback below distinguishes execute-after-commit loss.
    }
    if (result && result.meta.changes !== 0 && result.meta.changes !== 2) {
      fail("write_failed");
    }
    const run = await readRunById(database, fence.runId);
    if (
      run && run.runtimeGeneration === fence.runtimeGeneration &&
      run.leaseId === fence.leaseId && run.startedAt === fence.startedAt &&
      run.leaseRevision === nextRevision &&
      run.leaseUpdatedAt === renewedAt.iso && run.leaseExpiresAt === expiresAt &&
      (run.status === "running" || run.status === "sealed")
    ) {
      return {
        fence: fenceFromRun(run),
        kind: result?.meta.changes === 2 ? "committed" : "replayed",
        run,
      };
    }
    return { kind: "lost" };
  } catch (error) {
    redacted(error, "write_failed");
  }
}

export async function bindAlertEvaluatorRunAsOf(
  database: D1Database,
  fenceValue: AlertEvaluatorRunFence,
  input: BindAlertEvaluatorRunAsOfInput,
): Promise<AlertEvaluatorRunMutationResult> {
  try {
    if (arguments.length !== 3) fail("invalid_input");
    const fence = parseFence(fenceValue);
    const record = exactRecord(input, ["asOf", "boundAt"]);
    const asOf = canonicalTimestamp(record.asOf);
    const boundAt = canonicalTimestamp(record.boundAt);
    if (
      asOf.time < new Date(fence.startedAt).getTime() ||
      asOf.time > boundAt.time ||
      boundAt.time <= new Date(fence.leaseUpdatedAt).getTime() ||
      boundAt.time >= new Date(fence.leaseExpiresAt).getTime()
    ) {
      fail("invalid_input");
    }
    let result: D1Result | null = null;
    try {
      result = await database.prepare(
        `UPDATE alert_evaluator_run SET as_of = ?, updated_at = ?
        WHERE id = ? AND runtime_generation = ? AND lease_revision = ?
          AND lease_id = ? AND lease_updated_at = ? AND lease_expires_at = ?
          AND status = 'running' AND as_of IS NULL`,
      ).bind(
        asOf.iso,
        boundAt.iso,
        fence.runId,
        fence.runtimeGeneration,
        fence.leaseRevision,
        fence.leaseId,
        fence.leaseUpdatedAt,
        fence.leaseExpiresAt,
      ).run();
    } catch {
      // Exact readback below distinguishes execute-after-commit loss.
    }
    if (result && result.meta.changes !== 0 && result.meta.changes !== 1) {
      fail("write_failed");
    }
    const run = await readRunById(database, fence.runId);
    if (run && runMatchesFence(run, fence) && run.status === "running" &&
      run.asOf === asOf.iso && run.updatedAt === boundAt.iso) {
      return {
        fence,
        kind: result?.meta.changes === 1 ? "committed" : "replayed",
        run,
      };
    }
    return { kind: "lost" };
  } catch (error) {
    redacted(error, "write_failed");
  }
}

function parseSourceProjection(value: unknown): SourceProjection {
  const record = recordValue(value);
  let proof: AlertEvaluatorSourceProofValue;
  try {
    proof = parseAlertEvaluatorSourceProofValue({
      incompleteCount: record.incomplete_count,
      observationCount: record.observation_count,
      proofSha256: record.proof_sha256,
      sourceId: record.source_id,
      status: record.status,
    });
  } catch {
    fail("source_invalid");
  }
  return {
    as_of: sourceTimestamp(record.as_of),
    incomplete_count: proof.incompleteCount,
    observation_count: proof.observationCount,
    proof_sha256: proof.proofSha256,
    recorded_at: sourceTimestamp(record.recorded_at),
    run_id: uuidV4(record.run_id, "source_invalid"),
    runtime_generation: boundedInteger(
      record.runtime_generation,
      1,
      ALERT_RUNTIME_GENERATION_MAX,
      "source_invalid",
    ),
    runtime_revision: boundedInteger(
      record.runtime_revision,
      1,
      MAX_ACTIVE_REVISION,
      "source_invalid",
    ),
    source_id: proof.sourceId,
    status: proof.status,
  };
}

async function readSources(
  database: D1Database,
  runId: string,
): Promise<SourceProjection[]> {
  const rows = await database.prepare(
    `SELECT ${SOURCE_PROJECTION} FROM alert_evaluator_run_source
      WHERE run_id = ? ORDER BY source_id`,
  ).bind(runId).all();
  return rows.results.map(parseSourceProjection);
}

function sameSource(
  row: SourceProjection,
  fence: AlertEvaluatorRunFence,
  input: RecordAlertEvaluatorRunSourceInput,
  proof: AlertEvaluatorSourceProofValue,
): boolean {
  return row.run_id === fence.runId && row.source_id === proof.sourceId &&
    row.as_of === input.asOf && row.status === proof.status &&
    row.observation_count === proof.observationCount &&
    row.incomplete_count === proof.incompleteCount &&
    row.proof_sha256 === proof.proofSha256 &&
    row.runtime_generation === fence.runtimeGeneration &&
    row.runtime_revision === fence.leaseRevision &&
    row.recorded_at === input.recordedAt;
}

export async function recordAlertEvaluatorRunSource(
  database: D1Database,
  fenceValue: AlertEvaluatorRunFence,
  input: RecordAlertEvaluatorRunSourceInput,
): Promise<AlertEvaluatorProofWriteResult> {
  try {
    if (arguments.length !== 3) fail("invalid_input");
    const fence = parseFence(fenceValue);
    const record = exactRecord(input, ["asOf", "proof", "recordedAt"]);
    const asOf = canonicalTimestamp(record.asOf).iso;
    const recordedAt = canonicalTimestamp(record.recordedAt).iso;
    let proof: AlertEvaluatorSourceProofValue;
    try {
      proof = parseAlertEvaluatorSourceProofValue(record.proof);
    } catch {
      fail("invalid_input");
    }
    const normalized = { asOf, proof, recordedAt };
    const existing = (await readSources(database, fence.runId))
      .find(({ source_id }) => source_id === proof.sourceId);
    if (existing) {
      if (sameSource(existing, fence, normalized, proof)) return "replayed";
      fail("conflict");
    }
    let result: D1Result;
    try {
      result = await database.prepare(
        `INSERT INTO alert_evaluator_run_source
          (run_id, source_id, as_of, status, observation_count,
           incomplete_count, proof_sha256, runtime_generation,
           runtime_revision, recorded_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        fence.runId,
        proof.sourceId,
        asOf,
        proof.status,
        proof.observationCount,
        proof.incompleteCount,
        proof.proofSha256,
        fence.runtimeGeneration,
        fence.leaseRevision,
        recordedAt,
      ).run();
    } catch {
      const raced = (await readSources(database, fence.runId))
        .find(({ source_id }) => source_id === proof.sourceId);
      if (raced && sameSource(raced, fence, normalized, proof)) return "replayed";
      return "lost";
    }
    if (result.meta.changes !== 1) fail("write_failed");
    return "recorded";
  } catch (error) {
    redacted(error, "write_failed");
  }
}

function sourceProofValue(row: SourceProjection): AlertEvaluatorSourceProofValue {
  return {
    incompleteCount: row.incomplete_count,
    observationCount: row.observation_count,
    proofSha256: row.proof_sha256,
    sourceId: row.source_id as AlertEvaluatorSourceId,
    status: row.status as AlertEvaluatorSourceStatus,
  };
}

export async function sealAlertEvaluatorRunPlan(
  database: D1Database,
  fenceValue: AlertEvaluatorRunFence,
  input: SealAlertEvaluatorRunInput,
): Promise<AlertEvaluatorRunMutationResult> {
  try {
    if (arguments.length !== 3) fail("invalid_input");
    const fence = parseFence(fenceValue);
    const record = exactRecord(input, ["decisions", "sealedAt"]);
    if (!Array.isArray(record.decisions)) fail("invalid_input");
    const sealedAt = canonicalTimestamp(record.sealedAt);
    let decisions: AlertEvaluatorDecisionProofValue[];
    try {
      decisions = record.decisions.map(parseAlertEvaluatorDecisionProofValue);
    } catch {
      fail("invalid_input");
    }
    const run = await readRunById(database, fence.runId);
    if (!run || !runMatchesFence(run, fence)) return { kind: "lost" };
    const sources = await readSources(database, fence.runId);
    let sourceDigest: string;
    let decisionDigest: string;
    try {
      sourceDigest = await alertEvaluatorSourceManifestDigest(
        sources.map(sourceProofValue),
      );
      decisionDigest = await alertEvaluatorDecisionManifestDigest(decisions);
    } catch {
      fail("invalid_input");
    }
    const sourceStatus = new Map(
      sources.map((source) => [source.source_id, source.status]),
    );
    if (decisions.some((decision) =>
      decision.disposition === "suppressed_partial" &&
      sourceStatus.get(decision.sourceId) !== "partial"
    )) {
      fail("invalid_input");
    }
    const partialCount = sources.filter(({ status }) => status !== "complete").length;
    if (
      run.status === "sealed" && run.sourceManifestSha256 === sourceDigest &&
      run.decisionManifestSha256 === decisionDigest &&
      run.sourceCount === ALERT_EVALUATOR_SOURCE_IDS.length &&
      run.partialSourceCount === partialCount &&
      run.decisionCount === decisions.length && run.updatedAt === sealedAt.iso
    ) {
      return { fence, kind: "replayed", run };
    }
    if (
      run.status !== "running" || run.asOf === null ||
      sealedAt.time <= new Date(run.updatedAt).getTime() ||
      sealedAt.time >= new Date(run.leaseExpiresAt).getTime()
    ) {
      return { kind: "lost" };
    }
    let result: D1Result | null = null;
    try {
      result = await database.prepare(
        `UPDATE alert_evaluator_run
          SET status = 'sealed', source_count = 9, partial_source_count = ?,
              source_manifest_sha256 = ?, decision_count = ?,
              decision_manifest_sha256 = ?, updated_at = ?
        WHERE id = ? AND runtime_generation = ? AND lease_revision = ?
          AND lease_id = ? AND lease_updated_at = ? AND lease_expires_at = ?
          AND status = 'running' AND as_of = ? AND updated_at = ?`,
      ).bind(
        partialCount,
        sourceDigest,
        decisions.length,
        decisionDigest,
        sealedAt.iso,
        fence.runId,
        fence.runtimeGeneration,
        fence.leaseRevision,
        fence.leaseId,
        fence.leaseUpdatedAt,
        fence.leaseExpiresAt,
        run.asOf,
        run.updatedAt,
      ).run();
    } catch {
      // Exact readback below distinguishes execute-after-commit loss.
    }
    if (result && result.meta.changes !== 0 && result.meta.changes !== 1) {
      fail("write_failed");
    }
    const sealed = await readRunById(database, fence.runId);
    if (
      sealed && runMatchesFence(sealed, fence) && sealed.status === "sealed" &&
      sealed.sourceManifestSha256 === sourceDigest &&
      sealed.decisionManifestSha256 === decisionDigest &&
      sealed.partialSourceCount === partialCount &&
      sealed.decisionCount === decisions.length && sealed.updatedAt === sealedAt.iso
    ) {
      return {
        fence,
        kind: result?.meta.changes === 1 ? "committed" : "replayed",
        run: sealed,
      };
    }
    return { kind: "lost" };
  } catch (error) {
    redacted(error, "write_failed");
  }
}

function parseDecisionProjection(value: unknown): DecisionProjection {
  const record = recordValue(value);
  let proof: AlertEvaluatorDecisionProofValue;
  try {
    proof = parseAlertEvaluatorDecisionProofValue({
      decisionSha256: record.decision_sha256,
      disposition: record.disposition,
      evaluationSha256: record.evaluation_sha256,
      identitySha256: record.identity_sha256,
      ordinal: record.ordinal,
      sourceId: record.source_id,
    });
  } catch {
    fail("source_invalid");
  }
  return {
    as_of: sourceTimestamp(record.as_of),
    decision_sha256: proof.decisionSha256,
    disposition: proof.disposition,
    evaluation_sha256: proof.evaluationSha256,
    identity_sha256: proof.identitySha256,
    ordinal: proof.ordinal,
    recorded_at: sourceTimestamp(record.recorded_at),
    run_id: uuidV4(record.run_id, "source_invalid"),
    runtime_generation: boundedInteger(
      record.runtime_generation,
      1,
      ALERT_RUNTIME_GENERATION_MAX,
      "source_invalid",
    ),
    runtime_revision: boundedInteger(
      record.runtime_revision,
      1,
      MAX_ACTIVE_REVISION,
      "source_invalid",
    ),
    source_id: proof.sourceId,
    state_generation: nullableInteger(record.state_generation, 0, 1_000_000),
    state_id: record.state_id === null
      ? null
      : uuidV4(record.state_id, "source_invalid"),
    state_revision: nullableInteger(record.state_revision, 0, 1_000_000_000),
  };
}

async function readDecisions(
  database: D1Database,
  runId: string,
): Promise<DecisionProjection[]> {
  const rows = await database.prepare(
    `SELECT ${DECISION_PROJECTION} FROM alert_evaluator_run_decision
      WHERE run_id = ? ORDER BY ordinal`,
  ).bind(runId).all();
  return rows.results.map(parseDecisionProjection);
}

function publicDecision(row: DecisionProjection): AlertEvaluatorDecisionProof {
  return {
    asOf: row.as_of,
    decisionSha256: row.decision_sha256,
    disposition: row.disposition as AlertEvaluatorDecisionProofValue["disposition"],
    evaluationSha256: row.evaluation_sha256,
    identitySha256: row.identity_sha256,
    ordinal: row.ordinal,
    recordedAt: row.recorded_at,
    runId: row.run_id,
    runtimeGeneration: row.runtime_generation,
    runtimeRevision: row.runtime_revision,
    sourceId: row.source_id as AlertEvaluatorSourceId,
    stateGeneration: row.state_generation,
    stateId: row.state_id,
    stateRevision: row.state_revision,
  };
}

export async function readAlertEvaluatorDecisionProof(
  database: D1Database,
  options: {
    identitySha256: string;
    ordinal: number;
    runId: string;
  },
): Promise<AlertEvaluatorDecisionProof | null> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const record = exactRecord(options, ["identitySha256", "ordinal", "runId"]);
    const runId = uuidV4(record.runId, "invalid_input");
    const ordinal = boundedInteger(record.ordinal, 0, 9_999);
    let identitySha256: string;
    try {
      identitySha256 = parseAlertEvaluatorDigest(record.identitySha256);
    } catch {
      fail("invalid_input");
    }
    const rows = await database.prepare(
      `SELECT ${DECISION_PROJECTION}
         FROM alert_evaluator_run_decision
        WHERE run_id = ? AND (ordinal = ? OR identity_sha256 = ?)
        ORDER BY ordinal LIMIT 2`,
    ).bind(runId, ordinal, identitySha256).all();
    if (rows.results.length > 1) fail("source_invalid");
    return rows.results.length === 0
      ? null
      : publicDecision(parseDecisionProjection(rows.results[0]));
  } catch (error) {
    redacted(error, "source_unavailable");
  }
}

function decisionProofValue(
  row: DecisionProjection,
): AlertEvaluatorDecisionProofValue {
  return {
    decisionSha256: row.decision_sha256,
    disposition: row.disposition as AlertEvaluatorDecisionProofValue["disposition"],
    evaluationSha256: row.evaluation_sha256,
    identitySha256: row.identity_sha256,
    ordinal: row.ordinal,
    sourceId: row.source_id as AlertEvaluatorSourceId,
  };
}

function sameDecision(
  row: DecisionProjection,
  fence: AlertEvaluatorRunFence,
  proof: AlertEvaluatorDecisionProofValue,
  asOf: string,
  recordedAt: string,
): boolean {
  return row.run_id === fence.runId && row.source_id === proof.sourceId &&
    row.ordinal === proof.ordinal && row.identity_sha256 === proof.identitySha256 &&
    row.evaluation_sha256 === proof.evaluationSha256 &&
    row.decision_sha256 === proof.decisionSha256 &&
    row.disposition === proof.disposition && row.as_of === asOf &&
    row.state_id === null && row.state_generation === null &&
    row.state_revision === null &&
    row.runtime_generation === fence.runtimeGeneration &&
    row.runtime_revision === fence.leaseRevision &&
    row.recorded_at === recordedAt;
}

async function recordStatelessAlertEvaluatorDecision(
  database: D1Database,
  fenceValue: AlertEvaluatorRunFence,
  input:
    | RecordNoStateChangeAlertEvaluatorDecisionInput
    | RecordSuppressedAlertEvaluatorDecisionInput,
  expectedDisposition: "no_state_change" | "suppressed_partial",
): Promise<AlertEvaluatorProofWriteResult> {
  try {
    const fence = parseFence(fenceValue);
    const record = exactRecord(input, [
      ...(expectedDisposition === "no_state_change" ? ["absence"] : []),
      "asOf",
      "proof",
      "recordedAt",
    ]);
    const asOf = canonicalTimestamp(record.asOf).iso;
    const recordedAt = canonicalTimestamp(record.recordedAt).iso;
    let proof: AlertEvaluatorDecisionProofValue;
    try {
      proof = parseAlertEvaluatorDecisionProofValue(record.proof);
    } catch {
      fail("invalid_input");
    }
    if (proof.disposition !== expectedDisposition) fail("invalid_input");
    let absence: AlertEvaluatorNoStateAbsence | null = null;
    if (expectedDisposition === "no_state_change") {
      const absenceRecord = exactRecord(record.absence, [
        "environment",
        "queueName",
        "ruleId",
        "sourceKind",
        "subjectRef",
      ]);
      if (
        (absenceRecord.environment !== "local" &&
          absenceRecord.environment !== "preview" &&
          absenceRecord.environment !== "production") ||
        (absenceRecord.sourceKind !== "d1_exact" &&
          absenceRecord.sourceKind !== "queue_approximate") ||
        typeof absenceRecord.ruleId !== "string" ||
        (absenceRecord.queueName !== null &&
          typeof absenceRecord.queueName !== "string") ||
        (absenceRecord.subjectRef !== null &&
          typeof absenceRecord.subjectRef !== "string")
      ) {
        fail("invalid_input");
      }
      absence = {
        environment: absenceRecord.environment,
        queueName: absenceRecord.queueName,
        ruleId: absenceRecord.ruleId,
        sourceKind: absenceRecord.sourceKind,
        subjectRef: absenceRecord.subjectRef,
      };
    }
    const stateAbsent = async (): Promise<boolean> => {
      if (absence === null) return true;
      const count = await database.prepare(
        `SELECT count(*) AS count FROM alert_state
          WHERE rule_id = ? AND environment = ? AND source_kind = ?
            AND subject_ref IS ? AND queue_name IS ?`,
      ).bind(
        absence.ruleId,
        absence.environment,
        absence.sourceKind,
        absence.subjectRef,
        absence.queueName,
      ).first("count");
      return count === 0;
    };
    const existing = (await readDecisions(database, fence.runId))
      .find(({ ordinal }) => ordinal === proof.ordinal);
    if (existing) {
      if (sameDecision(existing, fence, proof, asOf, recordedAt) &&
        await stateAbsent()) return "replayed";
      fail("conflict");
    }
    let result: D1Result;
    try {
      const stateAbsenceSql = absence === null
        ? ""
        : ` WHERE NOT EXISTS (
              SELECT 1 FROM alert_state
               WHERE rule_id = ? AND environment = ? AND source_kind = ?
                 AND subject_ref IS ? AND queue_name IS ?
            )`;
      const statement = database.prepare(
        `INSERT INTO alert_evaluator_run_decision
          (run_id, source_id, ordinal, identity_sha256, evaluation_sha256,
           decision_sha256, disposition, as_of, state_id, state_generation,
           state_revision, runtime_generation, runtime_revision, recorded_at)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?
         ${stateAbsenceSql}`,
      );
      const bindings: unknown[] = [
        fence.runId,
        proof.sourceId,
        proof.ordinal,
        proof.identitySha256,
        proof.evaluationSha256,
        proof.decisionSha256,
        proof.disposition,
        asOf,
        fence.runtimeGeneration,
        fence.leaseRevision,
        recordedAt,
      ];
      if (absence !== null) {
        bindings.push(
          absence.ruleId,
          absence.environment,
          absence.sourceKind,
          absence.subjectRef,
          absence.queueName,
        );
      }
      result = await statement.bind(...bindings).run();
    } catch {
      const raced = (await readDecisions(database, fence.runId))
        .find(({ ordinal }) => ordinal === proof.ordinal);
      if (raced && sameDecision(raced, fence, proof, asOf, recordedAt) &&
        await stateAbsent()) {
        return "replayed";
      }
      return "lost";
    }
    if (result.meta.changes === 0 && absence !== null && !await stateAbsent()) {
      return "lost";
    }
    if (result.meta.changes !== 1) fail("write_failed");
    return "recorded";
  } catch (error) {
    redacted(error, "write_failed");
  }
}

export async function recordSuppressedAlertEvaluatorDecision(
  database: D1Database,
  fenceValue: AlertEvaluatorRunFence,
  input: RecordSuppressedAlertEvaluatorDecisionInput,
): Promise<AlertEvaluatorProofWriteResult> {
  if (arguments.length !== 3) fail("invalid_input");
  return recordStatelessAlertEvaluatorDecision(
    database,
    fenceValue,
    input,
    "suppressed_partial",
  );
}

export async function recordNoStateChangeAlertEvaluatorDecision(
  database: D1Database,
  fenceValue: AlertEvaluatorRunFence,
  input: RecordNoStateChangeAlertEvaluatorDecisionInput,
): Promise<AlertEvaluatorProofWriteResult> {
  if (arguments.length !== 3) fail("invalid_input");
  return recordStatelessAlertEvaluatorDecision(
    database,
    fenceValue,
    input,
    "no_state_change",
  );
}

async function verifySealedProof(
  database: D1Database,
  run: AlertEvaluatorRun,
): Promise<{ latestProofAt: number; sources: SourceProjection[] }> {
  if (
    run.status !== "sealed" || run.asOf === null ||
    run.sourceManifestSha256 === null || run.decisionManifestSha256 === null ||
    run.sourceCount !== ALERT_EVALUATOR_SOURCE_IDS.length ||
    run.partialSourceCount === null || run.decisionCount === null
  ) {
    fail("conflict");
  }
  const [sources, decisions] = await Promise.all([
    readSources(database, run.id),
    readDecisions(database, run.id),
  ]);
  let sourceDigest: string;
  let decisionDigest: string;
  try {
    sourceDigest = await alertEvaluatorSourceManifestDigest(
      sources.map(sourceProofValue),
    );
    decisionDigest = await alertEvaluatorDecisionManifestDigest(
      decisions.map(decisionProofValue),
    );
  } catch {
    fail("source_invalid");
  }
  if (
    sources.filter(({ status }) => status !== "complete").length !==
      run.partialSourceCount ||
    decisions.length !== run.decisionCount ||
    sourceDigest !== run.sourceManifestSha256 ||
    decisionDigest !== run.decisionManifestSha256
  ) {
    fail("source_invalid");
  }
  const times = [
    new Date(run.updatedAt).getTime(),
    ...sources.map(({ recorded_at }) => new Date(recorded_at).getTime()),
    ...decisions.map(({ recorded_at }) => new Date(recorded_at).getTime()),
  ];
  return { latestProofAt: Math.max(...times), sources };
}

async function terminalReplay(
  database: D1Database,
  fence: AlertEvaluatorRunFence,
  completedAt: string,
  failure: {
    errorCode: AlertEvaluatorRunErrorCode;
    status: AlertEvaluatorRunFailureStatus;
  } | null,
): Promise<
  Extract<AlertEvaluatorTerminalResult, { kind: "replayed" }> | null
> {
  const run = await readRunById(database, fence.runId);
  if (
    !run || !runMatchesFence(run, fence) || run.completedAt !== completedAt ||
    run.updatedAt !== completedAt ||
    run.terminalRuntimeRevision !== fence.leaseRevision + 1
  ) {
    return null;
  }
  if (
    failure === null && (
      run.status !== "succeeded" || run.asOf === null ||
      run.watermarkAt !== run.asOf || run.failureStatus !== null ||
      run.failureErrorCode !== null
    )
  ) {
    return null;
  }
  if (
    failure !== null && (
      run.status !== "failed" || run.watermarkAt !== null ||
      run.failureStatus !== failure.status ||
      run.failureErrorCode !== failure.errorCode
    )
  ) {
    return null;
  }
  const runtime = await readRuntime(database);
  if (
    runtime.generation !== fence.runtimeGeneration ||
    runtime.revision !== fence.leaseRevision + 1 || runtime.lease_id !== null ||
    runtime.lease_expires_at !== null ||
    runtime.last_started_at !== fence.startedAt ||
    runtime.updated_at !== completedAt ||
    (failure === null && (
      runtime.status !== "healthy" || runtime.watermark_at !== run.asOf ||
      runtime.last_success_at !== completedAt
    )) ||
    (failure !== null && (
      runtime.status !== failure.status ||
      runtime.last_error_at !== completedAt ||
      runtime.last_error_code !== failure.errorCode
    ))
  ) {
    return null;
  }
  const bootstrap = await database.prepare(
    `SELECT component FROM alert_evaluator_bootstrap
      WHERE component = 'evaluator'`,
  ).first("component");
  if (failure === null && bootstrap !== COMPONENT) fail("source_invalid");
  return { bootstrapCreated: false, kind: "replayed", run };
}

export async function recordAlertEvaluatorRunSuccess(
  database: D1Database,
  fenceValue: AlertEvaluatorRunFence,
  input: RecordAlertEvaluatorRunSuccessInput,
): Promise<AlertEvaluatorTerminalResult> {
  try {
    if (arguments.length !== 3) fail("invalid_input");
    const fence = parseFence(fenceValue);
    const record = exactRecord(input, ["completedAt"]);
    const completedAt = canonicalTimestamp(record.completedAt);
    const priorReplay = await terminalReplay(
      database,
      fence,
      completedAt.iso,
      null,
    );
    if (priorReplay) return priorReplay;
    const run = await readRunById(database, fence.runId);
    if (!run || !runMatchesFence(run, fence)) return { kind: "lost" };
    const verified = await verifySealedProof(database, run);
    if (
      run.partialSourceCount !== 0 ||
      verified.sources.some(({ status }) => status !== "complete") ||
      completedAt.time <= verified.latestProofAt ||
      completedAt.time >= new Date(fence.leaseExpiresAt).getTime() ||
      run.asOf === null
    ) {
      fail("conflict");
    }
    const nextRevision = fence.leaseRevision + 1;
    let results: D1Result[];
    try {
      results = await database.batch([
        database.prepare(
        `UPDATE alert_runtime_status
            SET status = 'healthy', revision = ?, lease_id = NULL,
                lease_expires_at = NULL, last_success_at = ?, watermark_at = ?,
                updated_at = ?
          WHERE component = 'evaluator' AND generation = ? AND revision = ?
            AND lease_id = ? AND lease_expires_at = ?
            AND last_started_at = ? AND updated_at = ?`,
      ).bind(
        nextRevision,
        completedAt.iso,
        run.asOf,
        completedAt.iso,
        fence.runtimeGeneration,
        fence.leaseRevision,
        fence.leaseId,
        fence.leaseExpiresAt,
        fence.startedAt,
        fence.leaseUpdatedAt,
        ),
        database.prepare(
        `INSERT INTO alert_evaluator_bootstrap
          (component, first_success_at, source_generation, source_revision)
         SELECT component, last_success_at, generation, revision
           FROM alert_runtime_status
          WHERE component = 'evaluator' AND status = 'healthy'
            AND generation = ? AND revision = ? AND lease_id IS NULL
            AND last_success_at = ? AND watermark_at = ?
            AND NOT EXISTS (SELECT 1 FROM alert_evaluator_bootstrap)
            AND changes() = 1`,
      ).bind(
        fence.runtimeGeneration,
        nextRevision,
        completedAt.iso,
        run.asOf,
        ),
      ]);
    } catch {
      const replay = await terminalReplay(
        database,
        fence,
        completedAt.iso,
        null,
      );
      if (replay) return replay;
      fail("write_failed");
    }
    const terminalChanges = results[0]?.meta.changes ?? -1;
    const bootstrapChanges = results[1]?.meta.changes ?? -1;
    if (
      terminalChanges !== 2 ||
      (bootstrapChanges !== 0 && bootstrapChanges !== 1)
    ) {
      const replay = await terminalReplay(
        database,
        fence,
        completedAt.iso,
        null,
      );
      if (replay) return replay;
      if (terminalChanges === 0 && bootstrapChanges === 0) {
        return { kind: "lost" };
      }
      fail("write_failed");
    }
    const committed = await readRunById(database, fence.runId);
    if (!committed || committed.status !== "succeeded" ||
      committed.completedAt !== completedAt.iso) fail("write_failed");
    return {
      bootstrapCreated: bootstrapChanges === 1,
      kind: "committed",
      run: committed,
    };
  } catch (error) {
    redacted(error, "write_failed");
  }
}

function validFailurePair(
  status: AlertEvaluatorRunFailureStatus,
  code: AlertEvaluatorRunErrorCode,
): boolean {
  return (status === "degraded" && code === "source_incomplete") ||
    (status === "unavailable" && code === "metrics_unavailable") ||
    (status === "failing" && (code === "evaluator_failed" || code === "unknown"));
}

export async function recordAlertEvaluatorRunFailure(
  database: D1Database,
  fenceValue: AlertEvaluatorRunFence,
  input: RecordAlertEvaluatorRunFailureInput,
): Promise<AlertEvaluatorTerminalResult> {
  try {
    if (arguments.length !== 3) fail("invalid_input");
    const fence = parseFence(fenceValue);
    const record = exactRecord(input, ["completedAt", "errorCode", "status"]);
    const completedAt = canonicalTimestamp(record.completedAt);
    const status = failureStatus(record.status);
    const code = errorCode(record.errorCode);
    if (status === null || code === null || !validFailurePair(status, code)) {
      fail("invalid_input");
    }
    const priorReplay = await terminalReplay(
      database,
      fence,
      completedAt.iso,
      { errorCode: code, status },
    );
    if (priorReplay) return priorReplay;
    const run = await readRunById(database, fence.runId);
    if (!run || !runMatchesFence(run, fence) ||
      (run.status !== "running" && run.status !== "sealed")) {
      return { kind: "lost" };
    }
    const proofTimes = [new Date(run.updatedAt).getTime()];
    const [sources, decisions] = await Promise.all([
      readSources(database, run.id),
      readDecisions(database, run.id),
    ]);
    proofTimes.push(
      ...sources.map(({ recorded_at }) => new Date(recorded_at).getTime()),
      ...decisions.map(({ recorded_at }) => new Date(recorded_at).getTime()),
    );
    if (
      completedAt.time <= Math.max(...proofTimes) ||
      completedAt.time >= new Date(fence.leaseExpiresAt).getTime()
    ) {
      fail("invalid_input");
    }
    let result: D1Result;
    try {
      result = await database.prepare(
        `UPDATE alert_runtime_status
          SET status = ?, revision = ?, lease_id = NULL,
              lease_expires_at = NULL, last_error_at = ?,
              last_error_code = ?, updated_at = ?
        WHERE component = 'evaluator' AND generation = ? AND revision = ?
          AND lease_id = ? AND lease_expires_at = ?
          AND last_started_at = ? AND updated_at = ?`,
      ).bind(
        status,
        fence.leaseRevision + 1,
        completedAt.iso,
        code,
        completedAt.iso,
        fence.runtimeGeneration,
        fence.leaseRevision,
        fence.leaseId,
        fence.leaseExpiresAt,
        fence.startedAt,
        fence.leaseUpdatedAt,
      ).run();
    } catch {
      const replay = await terminalReplay(
        database,
        fence,
        completedAt.iso,
        { errorCode: code, status },
      );
      if (replay) return replay;
      fail("write_failed");
    }
    if (result.meta.changes !== 0 && result.meta.changes !== 2) {
      fail("write_failed");
    }
    const replay = await terminalReplay(
      database,
      fence,
      completedAt.iso,
      { errorCode: code, status },
    );
    if (replay) {
      return result.meta.changes === 2
        ? { ...replay, kind: "committed" }
        : replay;
    }
    return { kind: "lost" };
  } catch (error) {
    redacted(error, "write_failed");
  }
}

// Used only by alert-state-repository to keep successful decision proof in the
// same D1 batch as its changes()-gated state/incident/outbox transition.
export function prepareAlertEvaluatorDecisionProofInsert(
  database: D1Database,
  fenceValue: AlertEvaluatorRunFence,
  input: {
    asOf: string;
    proof: AlertEvaluatorDecisionProofValue;
    recordedAt: string;
    stateGeneration: number | null;
    stateId: string | null;
    stateRevision: number | null;
  },
): D1PreparedStatement {
  const fence = parseFence(fenceValue);
  const record = exactRecord(input, [
    "asOf",
    "proof",
    "recordedAt",
    "stateGeneration",
    "stateId",
    "stateRevision",
  ]);
  const asOf = canonicalTimestamp(record.asOf).iso;
  const recordedAt = canonicalTimestamp(record.recordedAt).iso;
  let proof: AlertEvaluatorDecisionProofValue;
  try {
    proof = parseAlertEvaluatorDecisionProofValue(record.proof);
  } catch {
    fail("invalid_input");
  }
  if (proof.disposition !== "applied") fail("invalid_input");
  const stateId = record.stateId === null
    ? null
    : uuidV4(record.stateId, "invalid_input");
  const stateGeneration = record.stateGeneration === null
    ? null
    : boundedInteger(record.stateGeneration, 0, 1_000_000);
  const stateRevision = record.stateRevision === null
    ? null
    : boundedInteger(record.stateRevision, 0, 1_000_000_000);
  if (stateId === null || stateGeneration === null || stateRevision === null) {
    fail("invalid_input");
  }
  return database.prepare(
    `INSERT INTO alert_evaluator_run_decision
      (run_id, source_id, ordinal, identity_sha256, evaluation_sha256,
       decision_sha256, disposition, as_of, state_id, state_generation,
       state_revision, runtime_generation, runtime_revision, recorded_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      WHERE changes() = 1`,
  ).bind(
    fence.runId,
    proof.sourceId,
    proof.ordinal,
    proof.identitySha256,
    proof.evaluationSha256,
    proof.decisionSha256,
    proof.disposition,
    asOf,
    stateId,
    stateGeneration,
    stateRevision,
    fence.runtimeGeneration,
    fence.leaseRevision,
    recordedAt,
  );
}
