import {
  AUDIT_ALERT_RULE_IDS,
  AlertAuditSourceRepositoryError,
  readAuditAlertSources,
} from "./alert-audit-source-repository";
import {
  advanceAlertLifecycle,
  type AlertLifecycleResult,
  type AlertLifecycleState,
} from "./alert-evaluator";
import {
  AlertFanoutSourceRepositoryError,
  FANOUT_GAP_ALERT_RULE_ID,
  readFanoutGapAlertSource,
} from "./alert-fanout-source-repository";
import {
  AlertLogoutSourceRepositoryError,
  LOGOUT_DELIVERY_ALERT_RULE_ID,
  readLogoutDeliveryAlertSource,
} from "./alert-logout-source-repository";
import {
  AlertOAuthSourceRepositoryError,
  OAUTH_ALERT_RULE_ID,
  readOAuthAlertSource,
} from "./alert-oauth-source-repository";
import {
  AlertQueueSourceRepositoryError,
  readQueueMetricsAlertSource,
  type QueueMetricsProvider,
} from "./alert-queue-source-repository";
import {
  acquireAlertEvaluatorRun,
  bindAlertEvaluatorRunAsOf,
  recordAlertEvaluatorRunFailure,
  recordAlertEvaluatorRunSource,
  recordAlertEvaluatorRunSuccess,
  recordSuppressedAlertEvaluatorDecision,
  renewAlertEvaluatorRun,
  sealAlertEvaluatorRunPlan,
  type AcquireAlertEvaluatorRunResult,
  type AlertEvaluatorRun,
  type AlertEvaluatorRunFence,
  type AlertEvaluatorRunMutationResult,
  type AlertEvaluatorTerminalResult,
} from "./alert-run-repository";
import {
  ALERT_EVALUATOR_SOURCE_IDS,
  type AlertEvaluatorDecisionProofValue,
  type AlertEvaluatorSourceId,
  type AlertEvaluatorSourceProofValue,
} from "./alert-run-proof";
import {
  AlertRuntimeHealthSourceRepositoryError,
  readRuntimeHealthAlertSource,
  RUNTIME_HEALTH_ALERT_RULE_ID,
} from "./alert-runtime-health-source-repository";
import { initializeAlertEvaluatorRuntime } from "./alert-runtime-repository";
import {
  ALERT_QUEUE_NAMES,
  ALERT_RULE_IDS,
  evaluateAlertRule,
  parseAlertObservation,
  type AlertDimension,
  type AlertQueueName,
  type AlertRuleEvaluation,
  type AlertRuleId,
  type AlertRuleObservation,
  type AlertSeverity,
} from "./alert-rules";
import {
  persistAlertLifecycleDecision,
  readAlertLifecycleSnapshot,
  type AlertEnvironment,
  type AlertLifecycleSnapshot,
} from "./alert-state-repository";

const TRIGGER_CRON = "* * * * *";
const LEASE_DURATION_SECONDS = 240;
const RENEWAL_THRESHOLD_MILLISECONDS = 120_000;

// D1 counts every statement in a batch against the per-invocation query limit.
// These bounds include each repository's response-loss readback path. The
// per-item bound additionally includes one CAS conflict, recomputation, lease
// renewal, and a response-loss readback on both persistence attempts.
export const ALERT_EVALUATOR_D1_QUERY_BUDGET = Object.freeze({
  fixed: Object.freeze({
    acquireBindAndInitialize: 8,
    d1Sources: 15 + 4 + 2 + 9 + 2,
    queueSources: 4 * 3,
    runSourceProofs: 9 * 3,
    seal: 4,
    stageRenewals: 5 * 2,
    terminalWithFailureFallback: 9 + 8,
  }),
  freeInvocationLimit: 50,
  paidInvocationLimit: 1_000,
  perWorkItem: Object.freeze({
    conflictRenewal: 2,
    initialLifecycleSnapshot: 2,
    initialPersistenceWithReadback: 15,
    recomputedLifecycleSnapshot: 2,
    retryPersistenceWithReadback: 15,
  }),
  reservedPaidHeadroom: 150,
});

function sumQueryBudget(values: Readonly<Record<string, number>>): number {
  return Object.values(values).reduce((total, value) => total + value, 0);
}

export const ALERT_EVALUATOR_FIXED_D1_QUERY_BUDGET = sumQueryBudget(
  ALERT_EVALUATOR_D1_QUERY_BUDGET.fixed,
);
export const ALERT_EVALUATOR_PER_WORK_ITEM_D1_QUERY_BUDGET = sumQueryBudget(
  ALERT_EVALUATOR_D1_QUERY_BUDGET.perWorkItem,
);
export const ALERT_EVALUATOR_MAX_WORK_ITEMS = Math.floor(
  (
    ALERT_EVALUATOR_D1_QUERY_BUDGET.paidInvocationLimit -
    ALERT_EVALUATOR_D1_QUERY_BUDGET.reservedPaidHeadroom -
    ALERT_EVALUATOR_FIXED_D1_QUERY_BUDGET
  ) / ALERT_EVALUATOR_PER_WORK_ITEM_D1_QUERY_BUDGET,
);
export const ALERT_EVALUATOR_FREE_PLAN_SUPPORTED =
  ALERT_EVALUATOR_FIXED_D1_QUERY_BUDGET <=
    ALERT_EVALUATOR_D1_QUERY_BUDGET.freeInvocationLimit;

export type AlertEvaluatorMode = "disabled" | "observe_only";
export type AlertEvaluatorProofDigestDomain =
  | "decision"
  | "evaluation"
  | "identity"
  | "source";

export interface AlertEvaluatorQueueProviders {
  alert_deliveries_dlq: QueueMetricsProvider;
  audit_archive_dlq: QueueMetricsProvider;
  logout_deliveries_dlq: QueueMetricsProvider;
  security_events_dlq: QueueMetricsProvider;
}

export interface RunAlertEvaluatorInput {
  database: D1Database;
  environment: AlertEnvironment;
  hmacKeyBase64Url: string | null;
  mode: AlertEvaluatorMode;
  queueProviders: AlertEvaluatorQueueProviders;
  scheduledTime: number;
}

export type RunAlertEvaluatorResult =
  | { kind: "contended" }
  | { kind: "disabled" }
  | { kind: "duplicate"; run: AlertEvaluatorRun }
  | { kind: "initialized" }
  | { kind: "succeeded"; run: AlertEvaluatorRun };

export type AlertEvaluatorOrchestrationErrorCode =
  | "clock_invalid"
  | "evaluator_failed"
  | "lease_lost"
  | "metrics_unavailable"
  | "source_incomplete";

export class AlertEvaluatorOrchestrationError extends Error {
  readonly code: AlertEvaluatorOrchestrationErrorCode;

  constructor(code: AlertEvaluatorOrchestrationErrorCode) {
    super(`Alert evaluator orchestration failed (${code})`);
    this.name = "AlertEvaluatorOrchestrationError";
    this.code = code;
  }
}

interface SourceIncompleteIdentity {
  dimensionKind: AlertDimension["kind"];
  ruleId: AlertRuleId;
}

interface SourceReaderResult {
  incomplete: readonly SourceIncompleteIdentity[];
  observations: readonly AlertRuleObservation[];
}

interface CollectedSource {
  forcePartial: boolean;
  incomplete: readonly SourceIncompleteIdentity[];
  observations: readonly AlertRuleObservation[];
  planningObservations: readonly AlertRuleObservation[];
  proof: AlertEvaluatorSourceProofValue;
  sourceId: AlertEvaluatorSourceId;
}

interface PlannedDecision {
  decision: AlertLifecycleResult;
  evaluation: AlertRuleEvaluation;
  observation: AlertRuleObservation;
  proof: AlertEvaluatorDecisionProofValue;
  snapshot: AlertLifecycleSnapshot;
  sourceId: AlertEvaluatorSourceId;
  sourcePartial: boolean;
}

type SourceError =
  | AlertAuditSourceRepositoryError
  | AlertFanoutSourceRepositoryError
  | AlertLogoutSourceRepositoryError
  | AlertOAuthSourceRepositoryError
  | AlertQueueSourceRepositoryError
  | AlertRuntimeHealthSourceRepositoryError;

export interface AlertEvaluatorOrchestrationDependencies {
  acquireRun(
    database: D1Database,
    input: Parameters<typeof acquireAlertEvaluatorRun>[1],
  ): Promise<AcquireAlertEvaluatorRunResult>;
  bindRunAsOf(
    database: D1Database,
    fence: AlertEvaluatorRunFence,
    input: Parameters<typeof bindAlertEvaluatorRunAsOf>[2],
  ): Promise<AlertEvaluatorRunMutationResult>;
  clock(): Date;
  initializeRuntime(
    database: D1Database,
    input: Parameters<typeof initializeAlertEvaluatorRuntime>[1],
  ): Promise<boolean>;
  persistDecision(
    database: D1Database,
    input: Parameters<typeof persistAlertLifecycleDecision>[1],
  ): ReturnType<typeof persistAlertLifecycleDecision>;
  readAuditSource(
    database: D1Database,
    input: Parameters<typeof readAuditAlertSources>[1],
  ): ReturnType<typeof readAuditAlertSources>;
  readFanoutSource(
    database: D1Database,
    input: Parameters<typeof readFanoutGapAlertSource>[1],
  ): ReturnType<typeof readFanoutGapAlertSource>;
  readLifecycleSnapshot(
    database: D1Database,
    input: Parameters<typeof readAlertLifecycleSnapshot>[1],
  ): ReturnType<typeof readAlertLifecycleSnapshot>;
  readLogoutSource(
    database: D1Database,
    input: Parameters<typeof readLogoutDeliveryAlertSource>[1],
  ): ReturnType<typeof readLogoutDeliveryAlertSource>;
  readOAuthSource(
    database: D1Database,
    input: Parameters<typeof readOAuthAlertSource>[1],
  ): ReturnType<typeof readOAuthAlertSource>;
  readQueueSource(
    database: D1Database,
    provider: QueueMetricsProvider,
    input: Parameters<typeof readQueueMetricsAlertSource>[2],
    clock: Parameters<typeof readQueueMetricsAlertSource>[3],
  ): ReturnType<typeof readQueueMetricsAlertSource>;
  readRuntimeSource(
    database: D1Database,
    input: Parameters<typeof readRuntimeHealthAlertSource>[1],
  ): ReturnType<typeof readRuntimeHealthAlertSource>;
  recordFailure(
    database: D1Database,
    fence: AlertEvaluatorRunFence,
    input: Parameters<typeof recordAlertEvaluatorRunFailure>[2],
  ): Promise<AlertEvaluatorTerminalResult>;
  recordSource(
    database: D1Database,
    fence: AlertEvaluatorRunFence,
    input: Parameters<typeof recordAlertEvaluatorRunSource>[2],
  ): ReturnType<typeof recordAlertEvaluatorRunSource>;
  recordSuccess(
    database: D1Database,
    fence: AlertEvaluatorRunFence,
    input: Parameters<typeof recordAlertEvaluatorRunSuccess>[2],
  ): Promise<AlertEvaluatorTerminalResult>;
  recordSuppressedDecision(
    database: D1Database,
    fence: AlertEvaluatorRunFence,
    input: Parameters<typeof recordSuppressedAlertEvaluatorDecision>[2],
  ): ReturnType<typeof recordSuppressedAlertEvaluatorDecision>;
  renewRun(
    database: D1Database,
    fence: AlertEvaluatorRunFence,
    input: Parameters<typeof renewAlertEvaluatorRun>[2],
  ): Promise<AlertEvaluatorRunMutationResult>;
  sealRun(
    database: D1Database,
    fence: AlertEvaluatorRunFence,
    input: Parameters<typeof sealAlertEvaluatorRunPlan>[2],
  ): Promise<AlertEvaluatorRunMutationResult>;
}

const DEFAULT_DEPENDENCIES: AlertEvaluatorOrchestrationDependencies = {
  acquireRun: acquireAlertEvaluatorRun,
  bindRunAsOf: bindAlertEvaluatorRunAsOf,
  clock: () => new Date(),
  initializeRuntime: initializeAlertEvaluatorRuntime,
  persistDecision: persistAlertLifecycleDecision,
  readAuditSource: readAuditAlertSources,
  readFanoutSource: readFanoutGapAlertSource,
  readLifecycleSnapshot: readAlertLifecycleSnapshot,
  readLogoutSource: readLogoutDeliveryAlertSource,
  readOAuthSource: readOAuthAlertSource,
  readQueueSource: readQueueMetricsAlertSource,
  readRuntimeSource: readRuntimeHealthAlertSource,
  recordFailure: recordAlertEvaluatorRunFailure,
  recordSource: recordAlertEvaluatorRunSource,
  recordSuccess: recordAlertEvaluatorRunSuccess,
  recordSuppressedDecision: recordSuppressedAlertEvaluatorDecision,
  renewRun: renewAlertEvaluatorRun,
  sealRun: sealAlertEvaluatorRunPlan,
};

const RULE_ORDER = new Map(ALERT_RULE_IDS.map((ruleId, index) => [ruleId, index]));
const DIMENSION_ORDER: Readonly<Record<AlertDimension["kind"], number>> = {
  global: 0,
  subject_hmac: 1,
  actor_hmac: 2,
  client_hmac: 3,
  queue: 4,
};
const AUDIT_RULE_SET = new Set<AlertRuleId>(AUDIT_ALERT_RULE_IDS);

function fail(code: AlertEvaluatorOrchestrationErrorCode): never {
  throw new AlertEvaluatorOrchestrationError(code);
}

function canonicalTimestamp(value: unknown): { iso: string; time: number } {
  if (typeof value !== "string") fail("clock_invalid");
  const time = new Date(value).getTime();
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) {
    fail("clock_invalid");
  }
  return { iso: value, time };
}

function scheduledTimestamp(value: number): { iso: string; time: number } {
  if (!Number.isSafeInteger(value) || value < 0) fail("clock_invalid");
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) fail("clock_invalid");
  return { iso: date.toISOString(), time: date.getTime() };
}

function monotonicClock(source: () => Date): () => { iso: string; time: number } {
  let lastLogical: number | null = null;
  let lastRaw: number | null = null;
  return () => {
    let value: Date;
    try {
      value = source();
    } catch {
      fail("clock_invalid");
    }
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      fail("clock_invalid");
    }
    const raw = value.getTime();
    if (lastRaw !== null && raw < lastRaw) fail("clock_invalid");
    const time = lastLogical === null || raw > lastLogical
      ? raw
      : lastLogical + 1;
    if (!Number.isSafeInteger(time) || !Number.isFinite(new Date(time).getTime())) {
      fail("clock_invalid");
    }
    lastRaw = raw;
    lastLogical = time;
    return { iso: new Date(time).toISOString(), time };
  };
}

function canonicalJsonValue(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("invalid alert proof value");
    return value;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) {
        throw new TypeError("invalid alert proof value");
      }
    }
    return value.map(canonicalJsonValue);
  }
  if (typeof value !== "object" || value === null) {
    throw new TypeError("invalid alert proof value");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("invalid alert proof value");
  }
  const record = value as Record<string, unknown>;
  const canonical: Record<string, unknown> = {};
  for (const key of Object.keys(record).toSorted()) {
    if (record[key] === undefined) throw new TypeError("invalid alert proof value");
    canonical[key] = canonicalJsonValue(record[key]);
  }
  return canonical;
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export async function canonicalAlertEvaluatorProofDigest(
  domain: AlertEvaluatorProofDigestDomain,
  value: unknown,
): Promise<string> {
  const encoded = JSON.stringify([
    `pgid.alert.evaluator.${domain}.v1`,
    canonicalJsonValue(value),
  ]);
  return bytesToBase64url(new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(encoded),
  )));
}

function dimensionValue(dimension: AlertDimension): string {
  if (dimension.kind === "global") return "";
  if (dimension.kind === "queue") return dimension.queue;
  return `${dimension.reference.keyVersion}:${dimension.reference.value}`;
}

function compareCodePoints(left: string, right: string): number {
  const leftIterator = left[Symbol.iterator]();
  const rightIterator = right[Symbol.iterator]();
  while (true) {
    const leftPoint = leftIterator.next();
    const rightPoint = rightIterator.next();
    if (leftPoint.done || rightPoint.done) {
      return leftPoint.done === rightPoint.done ? 0 : leftPoint.done ? -1 : 1;
    }
    const difference = leftPoint.value.codePointAt(0)! -
      rightPoint.value.codePointAt(0)!;
    if (difference !== 0) return difference;
  }
}

function compareObservations(
  left: AlertRuleObservation,
  right: AlertRuleObservation,
): number {
  const rule = (RULE_ORDER.get(left.ruleId) ?? Number.MAX_SAFE_INTEGER) -
    (RULE_ORDER.get(right.ruleId) ?? Number.MAX_SAFE_INTEGER);
  if (rule !== 0) return rule;
  const dimension = DIMENSION_ORDER[left.dimension.kind] -
    DIMENSION_ORDER[right.dimension.kind];
  if (dimension !== 0) return dimension;
  return compareCodePoints(
    dimensionValue(left.dimension),
    dimensionValue(right.dimension),
  );
}

function semanticIdentity(observation: AlertRuleObservation): string {
  return JSON.stringify(canonicalJsonValue({
    dimension: observation.dimension,
    ruleId: observation.ruleId,
  }));
}

function sourceAllowsRule(
  sourceId: AlertEvaluatorSourceId,
  ruleId: AlertRuleId,
): boolean {
  if (sourceId === "d1.audit") return AUDIT_RULE_SET.has(ruleId);
  if (sourceId === "d1.oauth_client_report") return ruleId === OAUTH_ALERT_RULE_ID;
  if (sourceId === "d1.security_fanout_gap") {
    return ruleId === FANOUT_GAP_ALERT_RULE_ID;
  }
  if (sourceId === "d1.logout_delivery") {
    return ruleId === LOGOUT_DELIVERY_ALERT_RULE_ID;
  }
  if (sourceId === "d1.alert_runtime") {
    return ruleId === RUNTIME_HEALTH_ALERT_RULE_ID;
  }
  return ruleId === "pgid.queue.dlq_approximate.v1";
}

function sourceAllowsObservation(
  sourceId: AlertEvaluatorSourceId,
  observation: AlertRuleObservation,
): boolean {
  if (!sourceAllowsRule(sourceId, observation.ruleId)) return false;
  if (!sourceId.startsWith("queue.")) return true;
  return observation.dimension.kind === "queue" &&
    sourceId === `queue.${observation.dimension.queue}`;
}

function normalizeSourceResult(
  sourceId: AlertEvaluatorSourceId,
  result: SourceReaderResult,
  asOf: string,
): Pick<CollectedSource, "incomplete" | "observations"> {
  const observations = new Map<
    string,
    { canonical: string; observation: AlertRuleObservation }
  >();
  for (const candidate of result.observations) {
    const observation = parseAlertObservation(candidate);
    if (observation.asOf !== asOf || !sourceAllowsObservation(sourceId, observation)) {
      throw new TypeError("invalid alert source result");
    }
    const identity = semanticIdentity(observation);
    const canonical = JSON.stringify(canonicalJsonValue(observation));
    const existing = observations.get(identity);
    if (existing !== undefined && existing.canonical !== canonical) {
      throw new TypeError("invalid alert source result");
    }
    if (existing === undefined) {
      observations.set(identity, { canonical, observation });
    }
  }
  const incomplete = new Map<string, SourceIncompleteIdentity>();
  for (const candidate of result.incomplete) {
    if (
      !sourceAllowsRule(sourceId, candidate.ruleId) ||
      !Object.hasOwn(DIMENSION_ORDER, candidate.dimensionKind)
    ) {
      throw new TypeError("invalid alert source result");
    }
    const identity = {
      dimensionKind: candidate.dimensionKind,
      ruleId: candidate.ruleId,
    };
    incomplete.set(`${identity.ruleId}\0${identity.dimensionKind}`, identity);
  }
  return {
    incomplete: [...incomplete.values()].toSorted((left, right) =>
      compareCodePoints(left.ruleId, right.ruleId) ||
      compareCodePoints(left.dimensionKind, right.dimensionKind)
    ),
    observations: [...observations.values()]
      .map(({ observation }) => observation)
      .toSorted(compareObservations),
  };
}

function isKnownSourceError(error: unknown): error is SourceError {
  return error instanceof AlertAuditSourceRepositoryError ||
    error instanceof AlertFanoutSourceRepositoryError ||
    error instanceof AlertLogoutSourceRepositoryError ||
    error instanceof AlertOAuthSourceRepositoryError ||
    error instanceof AlertQueueSourceRepositoryError ||
    error instanceof AlertRuntimeHealthSourceRepositoryError;
}

function sourceErrorStatus(error: unknown): "invalid" | "unavailable" {
  if (!isKnownSourceError(error)) return "unavailable";
  return error.code === "invalid_input" || error.code === "source_invalid"
    ? "invalid"
    : "unavailable";
}

async function failedSource(
  sourceId: AlertEvaluatorSourceId,
  status: "invalid" | "unavailable",
): Promise<CollectedSource> {
  return {
    forcePartial: false,
    incomplete: [],
    observations: [],
    planningObservations: [],
    proof: {
      incompleteCount: 0,
      observationCount: 0,
      proofSha256: await canonicalAlertEvaluatorProofDigest("source", {
        sourceId,
        status,
      }),
      sourceId,
      status,
    },
    sourceId,
  };
}

async function completedSource(
  sourceId: AlertEvaluatorSourceId,
  result: SourceReaderResult,
  asOf: string,
): Promise<CollectedSource> {
  try {
    const normalized = normalizeSourceResult(sourceId, result, asOf);
    const status = normalized.incomplete.length === 0 ? "complete" : "partial";
    return {
      forcePartial: false,
      incomplete: normalized.incomplete,
      observations: normalized.observations,
      planningObservations: normalized.observations,
      proof: {
        incompleteCount: normalized.incomplete.length,
        observationCount: normalized.observations.length,
        proofSha256: await canonicalAlertEvaluatorProofDigest("source", {
          incomplete: normalized.incomplete,
          observations: normalized.observations,
          sourceId,
          status,
        }),
        sourceId,
        status,
      },
      sourceId,
    };
  } catch {
    return failedSource(sourceId, "invalid");
  }
}

async function collectSource(
  sourceId: AlertEvaluatorSourceId,
  reader: () => Promise<SourceReaderResult>,
  asOf: string,
): Promise<CollectedSource> {
  try {
    return completedSource(sourceId, await reader(), asOf);
  } catch (error) {
    return failedSource(sourceId, sourceErrorStatus(error));
  }
}

function queueSourceId(queue: AlertQueueName): AlertEvaluatorSourceId {
  return `queue.${queue}` as AlertEvaluatorSourceId;
}

function cachedProvider(result: PromiseSettledResult<unknown>): QueueMetricsProvider {
  return {
    async metrics(): Promise<unknown> {
      if (result.status === "fulfilled") return result.value;
      throw new Error("queue metrics unavailable");
    },
  };
}

interface QueueMetricBarrier {
  asOf: string;
  metrics: readonly PromiseSettledResult<unknown>[];
}

async function collectQueueMetricBarrier(
  input: RunAlertEvaluatorInput,
  nextTime: () => { iso: string; time: number },
): Promise<QueueMetricBarrier> {
  const pendingMetrics = ALERT_QUEUE_NAMES.map((queue) => {
    const provider = input.queueProviders[queue];
    try {
      return Promise.resolve(provider.metrics());
    } catch (error) {
      return Promise.reject(error);
    }
  });
  const metrics = await Promise.allSettled(pendingMetrics);
  const asOf = nextTime().iso;
  return { asOf, metrics };
}

async function collectQueueSources(
  input: RunAlertEvaluatorInput,
  dependencies: AlertEvaluatorOrchestrationDependencies,
  barrier: QueueMetricBarrier,
): Promise<CollectedSource[]> {
  const sources: CollectedSource[] = [];
  for (const [index, queue] of ALERT_QUEUE_NAMES.entries()) {
    const sourceId = queueSourceId(queue);
    const result = await collectSource(sourceId, async () => {
      const source = await dependencies.readQueueSource(
        input.database,
        cachedProvider(barrier.metrics[index]),
        { queueName: queue },
        () => new Date(barrier.asOf),
      );
      if (source.persistence === "unknown") {
        throw new AlertQueueSourceRepositoryError("source_unavailable");
      }
      return { incomplete: [], observations: [source.observation] };
    }, barrier.asOf);
    sources.push(result);
  }
  return sources;
}

async function collectD1Sources(
  input: RunAlertEvaluatorInput,
  dependencies: AlertEvaluatorOrchestrationDependencies,
  asOf: string,
): Promise<CollectedSource[]> {
  const specifications: readonly [
    AlertEvaluatorSourceId,
    () => Promise<SourceReaderResult>,
  ][] = [
    ["d1.audit", () => dependencies.readAuditSource(input.database, {
      asOf,
      environment: input.environment,
      hmacKeyBase64Url: input.hmacKeyBase64Url,
    })],
    ["d1.oauth_client_report", () => dependencies.readOAuthSource(
      input.database,
      {
        asOf,
        environment: input.environment,
        hmacKeyBase64Url: input.hmacKeyBase64Url,
      },
    )],
    ["d1.security_fanout_gap", () => dependencies.readFanoutSource(
      input.database,
      { asOf },
    )],
    ["d1.logout_delivery", () => dependencies.readLogoutSource(
      input.database,
      {
        asOf,
        environment: input.environment,
        hmacKeyBase64Url: input.hmacKeyBase64Url,
      },
    )],
    ["d1.alert_runtime", () => dependencies.readRuntimeSource(
      input.database,
      { asOf },
    )],
  ];
  const sources: CollectedSource[] = [];
  for (const [sourceId, reader] of specifications) {
    sources.push(await collectSource(sourceId, reader, asOf));
  }
  return sources;
}

async function invalidateConflictingSources(
  sources: CollectedSource[],
): Promise<CollectedSource[]> {
  const seen = new Map<
    string,
    {
      canonicals: Set<string>;
      sources: Set<AlertEvaluatorSourceId>;
    }
  >();
  for (const source of sources) {
    if (source.proof.status === "invalid" || source.proof.status === "unavailable") {
      continue;
    }
    const planningObservations: AlertRuleObservation[] = [];
    for (const observation of source.observations) {
      const identity = semanticIdentity(observation);
      const canonical = JSON.stringify(canonicalJsonValue(observation));
      const prior = seen.get(identity);
      if (prior === undefined) {
        seen.set(identity, {
          canonicals: new Set([canonical]),
          sources: new Set([source.sourceId]),
        });
        planningObservations.push(observation);
      } else {
        prior.canonicals.add(canonical);
        prior.sources.add(source.sourceId);
      }
    }
    source.planningObservations = planningObservations;
  }
  const invalid = new Set<AlertEvaluatorSourceId>();
  for (const { canonicals, sources: conflictingSources } of seen.values()) {
    if (canonicals.size < 2) continue;
    for (const sourceId of conflictingSources) invalid.add(sourceId);
  }
  return Promise.all(sources.map((source) =>
    invalid.has(source.sourceId) ? failedSource(source.sourceId, "invalid") : source
  ));
}

async function applyWorkCap(sources: CollectedSource[]): Promise<void> {
  const work = sources.flatMap((source) =>
    source.proof.status === "invalid" || source.proof.status === "unavailable"
      ? []
      : source.planningObservations.map((observation) => ({
          observation,
          source,
        }))
  ).toSorted((left, right) =>
    compareObservations(left.observation, right.observation)
  );
  if (ALERT_EVALUATOR_MAX_WORK_ITEMS < ALERT_EVALUATOR_SOURCE_IDS.length) {
    throw new TypeError("alert evaluator work cap cannot represent all sources");
  }
  // Reserve one canonical observation for every nonempty source in the closed
  // source order, then fill the remainder in global rule/dimension order. This
  // prevents one high-cardinality source from hiding all later source signals.
  const retained = new Set<AlertRuleObservation>();
  for (const source of sources) {
    const first = source.planningObservations[0];
    if (first !== undefined) retained.add(first);
  }
  for (const { observation } of work) {
    if (retained.size >= ALERT_EVALUATOR_MAX_WORK_ITEMS) break;
    retained.add(observation);
  }
  for (const source of sources) {
    if (source.proof.status === "invalid" || source.proof.status === "unavailable") {
      continue;
    }
    const sourceWorkCount = source.planningObservations.length;
    source.planningObservations = source.planningObservations.filter(
      (observation) => retained.has(observation),
    );
    const dropped = sourceWorkCount - source.planningObservations.length;
    if (dropped === 0) continue;
    source.forcePartial = true;
    const incompleteCount = source.incomplete.length + dropped;
    if (incompleteCount > 10_000) {
      throw new TypeError("alert evaluator incomplete count exceeds proof bound");
    }
    source.proof = {
      incompleteCount,
      observationCount: source.observations.length,
      proofSha256: await canonicalAlertEvaluatorProofDigest("source", {
        droppedByWorkCap: dropped,
        incomplete: source.incomplete,
        observations: source.observations,
        sourceId: source.sourceId,
        status: "partial",
      }),
      sourceId: source.sourceId,
      status: "partial",
    };
  }
}

function observationIsPartial(
  source: CollectedSource,
  observation: AlertRuleObservation,
): boolean {
  return source.forcePartial || source.incomplete.some((item) =>
    item.ruleId === observation.ruleId &&
    item.dimensionKind === observation.dimension.kind
  );
}

function severityRank(value: AlertSeverity | null): number {
  return value === "critical" ? 2 : value === "warning" ? 1 : 0;
}

function partialDecisionAllowed(
  evaluation: AlertRuleEvaluation,
  previous: AlertLifecycleState,
): boolean {
  if (evaluation.evidence !== "known" || evaluation.severity === "none") {
    return false;
  }
  return severityRank(evaluation.severity) >=
    Math.max(severityRank(previous.status), severityRank(previous.breachSeverity));
}

async function decisionProof(
  environment: AlertEnvironment,
  observation: AlertRuleObservation,
  evaluation: AlertRuleEvaluation,
  decision: AlertLifecycleResult,
  disposition: AlertEvaluatorDecisionProofValue["disposition"],
  ordinal: number,
  sourceId: AlertEvaluatorSourceId,
): Promise<AlertEvaluatorDecisionProofValue> {
  const identity = {
    dimension: observation.dimension,
    environment,
    ruleId: observation.ruleId,
  };
  return {
    decisionSha256: await canonicalAlertEvaluatorProofDigest("decision", decision),
    disposition,
    evaluationSha256: await canonicalAlertEvaluatorProofDigest(
      "evaluation",
      evaluation,
    ),
    identitySha256: await canonicalAlertEvaluatorProofDigest("identity", identity),
    ordinal,
    sourceId,
  };
}

async function planDecisions(
  input: RunAlertEvaluatorInput,
  dependencies: AlertEvaluatorOrchestrationDependencies,
  sources: readonly CollectedSource[],
  asOf: string,
): Promise<PlannedDecision[]> {
  const work = sources.flatMap((source) =>
    source.planningObservations.map((observation) => ({ observation, source }))
  ).toSorted((left, right) => compareObservations(left.observation, right.observation));
  const plans: PlannedDecision[] = [];
  for (const [ordinal, item] of work.entries()) {
    const evaluation = evaluateAlertRule(item.observation);
    if (evaluation.asOf !== asOf) fail("evaluator_failed");
    const snapshot = await dependencies.readLifecycleSnapshot(input.database, {
      dimension: item.observation.dimension,
      environment: input.environment,
      ruleId: item.observation.ruleId,
    });
    const decision = advanceAlertLifecycle({
      asOf,
      observation: item.observation,
      previous: snapshot.previous,
    });
    const sourcePartial = observationIsPartial(item.source, item.observation);
    const disposition = sourcePartial &&
        !partialDecisionAllowed(evaluation, snapshot.previous)
      ? "suppressed_partial"
      : decision.state.identity === null ? "no_state_change" : "applied";
    const proof = await decisionProof(
      input.environment,
      item.observation,
      evaluation,
      decision,
      disposition,
      ordinal,
      item.source.sourceId,
    );
    plans.push({
      decision,
      evaluation,
      observation: item.observation,
      proof,
      snapshot,
      sourceId: item.source.sourceId,
      sourcePartial,
    });
  }
  return plans;
}

function sameProof(
  left: AlertEvaluatorDecisionProofValue,
  right: AlertEvaluatorDecisionProofValue,
): boolean {
  return left.decisionSha256 === right.decisionSha256 &&
    left.disposition === right.disposition &&
    left.evaluationSha256 === right.evaluationSha256 &&
    left.identitySha256 === right.identitySha256 &&
    left.ordinal === right.ordinal && left.sourceId === right.sourceId;
}

async function recomputePlan(
  input: RunAlertEvaluatorInput,
  dependencies: AlertEvaluatorOrchestrationDependencies,
  plan: PlannedDecision,
): Promise<PlannedDecision> {
  const snapshot = await dependencies.readLifecycleSnapshot(input.database, {
    dimension: plan.observation.dimension,
    environment: input.environment,
    ruleId: plan.observation.ruleId,
  });
  const evaluation = evaluateAlertRule(plan.observation);
  const decision = advanceAlertLifecycle({
    asOf: evaluation.asOf,
    observation: plan.observation,
    previous: snapshot.previous,
  });
  const disposition = plan.sourcePartial &&
      !partialDecisionAllowed(evaluation, snapshot.previous)
    ? "suppressed_partial"
    : decision.state.identity === null ? "no_state_change" : "applied";
  const proof = await decisionProof(
    input.environment,
    plan.observation,
    evaluation,
    decision,
    disposition,
    plan.proof.ordinal,
    plan.sourceId,
  );
  return { ...plan, decision, evaluation, proof, snapshot };
}

function failureDisposition(sources: readonly CollectedSource[]): {
  code: AlertEvaluatorOrchestrationErrorCode;
  errorCode: "evaluator_failed" | "metrics_unavailable" | "source_incomplete";
  status: "degraded" | "failing" | "unavailable";
} | null {
  if (sources.some(({ proof }) => proof.status === "invalid")) {
    return { code: "evaluator_failed", errorCode: "evaluator_failed", status: "failing" };
  }
  if (sources.some(({ proof }) => proof.status === "unavailable")) {
    // Migration 0022 intentionally uses this fixed code for any unavailable
    // Queue provider or D1 source query, not only Queue metric failures.
    return {
      code: "metrics_unavailable",
      errorCode: "metrics_unavailable",
      status: "unavailable",
    };
  }
  if (sources.some(({ proof }) => proof.status === "partial")) {
    return {
      code: "source_incomplete",
      errorCode: "source_incomplete",
      status: "degraded",
    };
  }
  return null;
}

function resolveDependencies(
  overrides: Partial<AlertEvaluatorOrchestrationDependencies>,
): AlertEvaluatorOrchestrationDependencies {
  return { ...DEFAULT_DEPENDENCIES, ...overrides };
}

export async function runAlertEvaluator(
  input: RunAlertEvaluatorInput,
  overrides: Partial<AlertEvaluatorOrchestrationDependencies> = {},
): Promise<RunAlertEvaluatorResult> {
  if (input.mode === "disabled") return { kind: "disabled" };
  if (input.mode !== "observe_only") fail("evaluator_failed");

  const dependencies = resolveDependencies(overrides);
  const nextTime = monotonicClock(dependencies.clock);
  const scheduledAt = scheduledTimestamp(input.scheduledTime);
  const startedAt = nextTime();
  if (scheduledAt.time > startedAt.time) fail("clock_invalid");

  let fence: AlertEvaluatorRunFence | null = null;
  let failureAttempted = false;
  let ownershipLost = false;
  let terminal = false;

  const maybeRenew = async (): Promise<void> => {
    if (fence === null) fail("lease_lost");
    const checkedAt = nextTime();
    const expiresAt = canonicalTimestamp(fence.leaseExpiresAt);
    if (expiresAt.time - checkedAt.time > RENEWAL_THRESHOLD_MILLISECONDS) return;
    const result = await dependencies.renewRun(input.database, fence, {
      leaseDurationSeconds: LEASE_DURATION_SECONDS,
      renewedAt: checkedAt.iso,
    });
    if (result.kind === "lost") {
      ownershipLost = true;
      fail("lease_lost");
    }
    fence = result.fence;
  };

  const terminateFailure = async (
    code: "evaluator_failed" | "metrics_unavailable" | "source_incomplete",
    status: "degraded" | "failing" | "unavailable",
  ): Promise<boolean> => {
    if (fence === null || ownershipLost || terminal) return terminal;
    if (failureAttempted) return false;
    const completedAt = nextTime();
    failureAttempted = true;
    const result = await dependencies.recordFailure(input.database, fence, {
      completedAt: completedAt.iso,
      errorCode: code,
      status,
    });
    if (result.kind === "lost") {
      ownershipLost = true;
      return false;
    }
    terminal = true;
    return true;
  };

  try {
    if (await dependencies.initializeRuntime(input.database, {
      initializedAt: startedAt.iso,
    })) {
      return { kind: "initialized" };
    }
    const acquired = await dependencies.acquireRun(input.database, {
      leaseDurationSeconds: LEASE_DURATION_SECONDS,
      scheduledAt: scheduledAt.iso,
      startedAt: startedAt.iso,
      triggerCron: TRIGGER_CRON,
    });
    if (acquired === null) return { kind: "contended" };
    if (acquired.kind === "duplicate") {
      return { kind: "duplicate", run: acquired.run };
    }
    fence = acquired.fence;

    const queueBarrier = await collectQueueMetricBarrier(input, nextTime);
    const boundAt = nextTime();
    const bound = await dependencies.bindRunAsOf(input.database, fence, {
      asOf: queueBarrier.asOf,
      boundAt: boundAt.iso,
    });
    if (bound.kind === "lost") {
      ownershipLost = true;
      fail("lease_lost");
    }
    fence = bound.fence;
    await maybeRenew();

    const queueSources = await collectQueueSources(
      input,
      dependencies,
      queueBarrier,
    );
    const d1 = await collectD1Sources(input, dependencies, queueBarrier.asOf);
    const sources = await invalidateConflictingSources([...queueSources, ...d1]);
    if (
      sources.length !== ALERT_EVALUATOR_SOURCE_IDS.length ||
      sources.some((source, index) =>
        source.sourceId !== ALERT_EVALUATOR_SOURCE_IDS[index]
      )
    ) {
      fail("evaluator_failed");
    }
    await applyWorkCap(sources);
    await maybeRenew();

    for (const source of sources) {
      const result = await dependencies.recordSource(input.database, fence, {
        asOf: queueBarrier.asOf,
        proof: source.proof,
        recordedAt: nextTime().iso,
      });
      if (result === "lost") {
        ownershipLost = true;
        fail("lease_lost");
      }
    }
    await maybeRenew();

    const plans = await planDecisions(
      input,
      dependencies,
      sources,
      queueBarrier.asOf,
    );
    await maybeRenew();
    const sealed = await dependencies.sealRun(input.database, fence, {
      decisions: plans.map(({ proof }) => proof),
      sealedAt: nextTime().iso,
    });
    if (sealed.kind === "lost") {
      ownershipLost = true;
      fail("lease_lost");
    }
    fence = sealed.fence;

    for (const [index, originalPlan] of plans.entries()) {
      if (index > 0 && index % 25 === 0) await maybeRenew();
      const recordedAt = nextTime().iso;
      if (originalPlan.proof.disposition === "suppressed_partial") {
        const result = await dependencies.recordSuppressedDecision(
          input.database,
          fence,
          {
            asOf: originalPlan.evaluation.asOf,
            proof: { ...originalPlan.proof, disposition: "suppressed_partial" },
            recordedAt,
          },
        );
        if (result === "lost") {
          ownershipLost = true;
          fail("lease_lost");
        }
        continue;
      }
      let plan = originalPlan;
      let result = await dependencies.persistDecision(input.database, {
        decision: plan.decision,
        environment: input.environment,
        evaluation: plan.evaluation,
        expected: plan.snapshot.expected,
        runProof: {
          fence,
          proof: plan.proof.disposition === "applied"
            ? { ...plan.proof, disposition: "applied" }
            : { ...plan.proof, disposition: "no_state_change" },
          recordedAt,
        },
      });
      if (result === "conflict") {
        const recomputed = await recomputePlan(input, dependencies, plan);
        if (!sameProof(recomputed.proof, plan.proof)) fail("evaluator_failed");
        plan = recomputed;
        await maybeRenew();
        result = await dependencies.persistDecision(input.database, {
          decision: plan.decision,
          environment: input.environment,
          evaluation: plan.evaluation,
          expected: plan.snapshot.expected,
          runProof: {
            fence,
            proof: plan.proof.disposition === "applied"
              ? { ...plan.proof, disposition: "applied" }
              : { ...plan.proof, disposition: "no_state_change" },
            recordedAt: nextTime().iso,
          },
        });
      }
      if (result === "conflict") fail("evaluator_failed");
    }

    await maybeRenew();
    const sourceFailure = failureDisposition(sources);
    if (sourceFailure !== null) {
      let terminalized: boolean;
      try {
        terminalized = await terminateFailure(
          sourceFailure.errorCode,
          sourceFailure.status,
        );
      } catch (error) {
        if (failureAttempted) fail(sourceFailure.code);
        throw error;
      }
      if (!terminalized) {
        fail("lease_lost");
      }
      fail(sourceFailure.code);
    }
    const completedAt = nextTime();
    const success = await dependencies.recordSuccess(input.database, fence, {
      completedAt: completedAt.iso,
    });
    if (success.kind === "lost") {
      ownershipLost = true;
      fail("lease_lost");
    }
    terminal = true;
    return { kind: "succeeded", run: success.run };
  } catch (error) {
    let code = error instanceof AlertEvaluatorOrchestrationError
      ? error.code
      : "evaluator_failed";
    if (!terminal && !ownershipLost && fence !== null && !failureAttempted) {
      try {
        if (!await terminateFailure("evaluator_failed", "failing") && ownershipLost) {
          code = "lease_lost";
        }
      } catch {
        // A later exact-expiry takeover owns recovery when terminalization fails.
      }
    }
    throw new AlertEvaluatorOrchestrationError(code);
  }
}
