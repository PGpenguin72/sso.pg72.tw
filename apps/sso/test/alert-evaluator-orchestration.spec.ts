import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";

import {
  AlertAuditSourceRepositoryError,
  ALERT_HASH_KEY_SENTINEL_DOMAIN,
  deriveAlertHashKeyFingerprintV1,
  type AuditAlertObservation,
  type AuditAlertSourceResult,
} from "../worker/alert-audit-source-repository";
import {
  advanceAlertLifecycle,
  inactiveAlertState,
  type AlertLifecycleState,
} from "../worker/alert-evaluator";
import type {
  FanoutGapAlertObservation,
  FanoutGapAlertSourceResult,
} from "../worker/alert-fanout-source-repository";
import type {
  LogoutDeliveryAlertObservation,
  LogoutDeliveryAlertSourceResult,
} from "../worker/alert-logout-source-repository";
import type {
  OAuthAlertObservation,
  OAuthAlertSourceResult,
} from "../worker/alert-oauth-source-repository";
import {
  ALERT_EVALUATOR_D1_QUERY_BUDGET,
  ALERT_EVALUATOR_FIXED_D1_QUERY_BUDGET,
  ALERT_EVALUATOR_FREE_PLAN_SUPPORTED,
  ALERT_EVALUATOR_MAX_WORK_ITEMS,
  ALERT_EVALUATOR_PER_WORK_ITEM_D1_QUERY_BUDGET,
  AlertEvaluatorOrchestrationError,
  canonicalAlertEvaluatorProofDigest,
  runAlertEvaluator,
  type AlertEvaluatorOrchestrationDependencies,
  type AlertEvaluatorQueueProviders,
} from "../worker/alert-evaluator-orchestration";
import type { QueueMetricsAlertObservation } from "../worker/alert-queue-source-repository";
import {
  ALERT_EVALUATOR_SOURCE_IDS,
  type AlertEvaluatorDecisionProofValue,
  type AlertEvaluatorSourceProofValue,
} from "../worker/alert-run-proof";
import {
  type AlertEvaluatorRun,
  type AlertEvaluatorRunFence,
  type RecordAlertEvaluatorRunFailureInput,
} from "../worker/alert-run-repository";
import type {
  RuntimeHealthAlertObservation,
  RuntimeHealthAlertSourceResult,
} from "../worker/alert-runtime-health-source-repository";
import {
  ALERT_QUEUE_NAMES,
  type AlertQueueName,
} from "../worker/alert-rules";
import {
  type AlertLifecycleSnapshot,
  type PersistAlertLifecycleDecisionInput,
} from "../worker/alert-state-repository";

const BASE_TIME = Date.parse("2035-07-18T00:00:00.000Z");
const EXPECTED_AS_OF = new Date(BASE_TIME + 2_000).toISOString();
const RUN_ID = "11111111-1111-4111-8111-111111111111";
const LEASE_ID = "22222222-2222-4222-8222-222222222222";
const STATE_ID = "33333333-3333-4333-8333-333333333333";
const INCIDENT_ID = "44444444-4444-4444-8444-444444444444";

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

const TEST_HMAC_KEY = base64Url(
  Uint8Array.from({ length: 32 }, (_, index) => index + 1),
);

function at(offsetMilliseconds: number): string {
  return new Date(BASE_TIME + offsetMilliseconds).toISOString();
}

function queueObservation(
  asOf: string,
  queue: AlertQueueName,
): QueueMetricsAlertObservation {
  return {
    asOf,
    dimension: { kind: "queue", queue },
    ruleId: "pgid.queue.dlq_approximate.v1",
    snapshot: {
      backlogBytes: 0,
      backlogCount: 0,
      consecutiveNonzeroSamples: 0,
      nonzeroSinceAt: null,
      oldestMessageTimestamp: null,
      sampledAt: asOf,
    },
  };
}

function registrationObservation(
  asOf: string,
  count: number,
): AuditAlertObservation {
  return {
    asOf,
    dimension: { kind: "global" },
    ruleId: "pgid.registration.rate_limited.v1",
    windows: {
      "5m": { count },
      "15m": { count },
      "60m": { count },
    },
  };
}

function restrictedObservation(
  asOf: string,
  reference: string,
): AuditAlertObservation {
  return {
    asOf,
    dimension: {
      kind: "subject_hmac",
      reference: { keyVersion: 1, value: reference },
    },
    ruleId: "pgid.restricted.sensitive_denied.v1",
    windows: {
      "5m": { count: 3, knownSurfaces: 1 },
      "15m": { count: 3, knownSurfaces: 1 },
      "60m": { count: 3, knownSurfaces: 1 },
    },
  };
}

function oauthObservation(asOf: string): OAuthAlertObservation {
  return {
    asOf,
    dimension: {
      kind: "client_hmac",
      reference: { keyVersion: 1, value: "Q".repeat(43) },
    },
    ruleId: "pgid.oauth.client_report.v1",
    windows: {
      "5m": { count: 1, distinctReporters: 1, highRiskCount: 1 },
      "15m": { count: 1, distinctReporters: 1, highRiskCount: 1 },
      "60m": { count: 1, distinctReporters: 1, highRiskCount: 1 },
    },
  };
}

function fanoutObservation(asOf: string): FanoutGapAlertObservation {
  return {
    asOf,
    dimension: { kind: "global" },
    ruleId: "pgid.security.fanout_gap.v1",
    snapshot: {
      missingOlderThan15mCount: 0,
      missingOlderThan5mCount: 0,
    },
  };
}

function logoutObservation(asOf: string): LogoutDeliveryAlertObservation {
  const empty = { eligible: 0, leaseExpired: 0, unresolved: 0 };
  return {
    asOf,
    current: {
      currentDead: 0,
      currentUnresolved: 0,
      oldestUnresolvedAgeSeconds: null,
    },
    dimension: { kind: "global" },
    ruleId: "pgid.logout.delivery_health.v1",
    windows: { "5m": empty, "15m": empty, "60m": empty },
  };
}

function runtimeObservation(asOf: string): RuntimeHealthAlertObservation {
  return {
    asOf,
    dimension: { kind: "global" },
    ruleId: "pgid.alert.runtime_health.v1",
    snapshot: {
      deadOutbox: 0,
      evaluatorAgeSeconds: 0,
      outboxDueAgeSeconds: null,
    },
  };
}

function healthyQueueProviders(): AlertEvaluatorQueueProviders {
  return {
    alert_deliveries_dlq: { async metrics() { return {}; } },
    audit_archive_dlq: { async metrics() { return {}; } },
    logout_deliveries_dlq: { async metrics() { return {}; } },
    security_events_dlq: { async metrics() { return {}; } },
  };
}

function activeWarningState(): AlertLifecycleState {
  const first = advanceAlertLifecycle({
    asOf: at(-120_000),
    observation: registrationObservation(at(-120_000), 5),
    previous: inactiveAlertState(),
  });
  return advanceAlertLifecycle({
    asOf: at(-60_000),
    observation: registrationObservation(at(-60_000), 5),
    previous: first.state,
  }).state;
}

function activeSnapshot(previous = activeWarningState()): AlertLifecycleSnapshot {
  if (previous.lastEvaluatedAt === null) throw new Error("expected active state");
  return {
    expected: {
      generation: 1,
      incident: { id: INCIDENT_ID, status: "open" },
      lastEvaluatedAt: previous.lastEvaluatedAt,
      revision: 1,
      stateId: STATE_ID,
    },
    previous,
  };
}

function pendingCriticalEscalationState(): AlertLifecycleState {
  return advanceAlertLifecycle({
    asOf: at(-30_000),
    observation: registrationObservation(at(-30_000), 40),
    previous: activeWarningState(),
  }).state;
}

function fakeRun(
  fence: AlertEvaluatorRunFence,
  status: AlertEvaluatorRun["status"],
  overrides: Partial<AlertEvaluatorRun> = {},
): AlertEvaluatorRun {
  return {
    acquiredRevision: 1,
    asOf: status === "running" ? null : EXPECTED_AS_OF,
    completedAt: status === "failed" || status === "succeeded" ? at(50_000) : null,
    createdAt: fence.startedAt,
    decisionCount: status === "running" ? null : 0,
    decisionManifestSha256: status === "running" ? null : "A".repeat(43),
    failureErrorCode: status === "failed" ? "evaluator_failed" : null,
    failureStatus: status === "failed" ? "failing" : null,
    id: fence.runId,
    leaseExpiresAt: fence.leaseExpiresAt,
    leaseId: fence.leaseId,
    leaseRevision: fence.leaseRevision,
    leaseUpdatedAt: fence.leaseUpdatedAt,
    partialSourceCount: status === "running" ? null : 0,
    runtimeGeneration: fence.runtimeGeneration,
    sourceCount: status === "running" ? null : 9,
    sourceManifestSha256: status === "running" ? null : "E".repeat(43),
    startedAt: fence.startedAt,
    status,
    terminalRuntimeRevision: status === "failed" || status === "succeeded"
      ? fence.leaseRevision + 1
      : null,
    triggerCron: "* * * * *",
    triggerScheduledAt: at(0),
    updatedAt: status === "running" ? fence.leaseUpdatedAt : at(50_000),
    watermarkAt: status === "succeeded" ? EXPECTED_AS_OF : null,
    ...overrides,
  };
}

interface HarnessOptions {
  auditError?: Error;
  auditResult?: AuditAlertSourceResult;
  fanoutResult?: FanoutGapAlertSourceResult;
  initialize?: boolean;
  logoutResult?: LogoutDeliveryAlertSourceResult;
  mutationOutcome?: "committed" | "replayed";
  oauthResult?: OAuthAlertSourceResult;
  persist?: (
    input: PersistAlertLifecycleDecisionInput,
    attempt: number,
  ) => "applied" | "conflict" | "duplicate" | Promise<"applied" | "conflict" | "duplicate">;
  proofOutcome?: "recorded" | "replayed";
  recordFailureLost?: boolean;
  recordFailureThrows?: boolean;
  renewOutcome?: "committed" | "lost" | "replayed";
  runtimeResult?: RuntimeHealthAlertSourceResult;
  shortLease?: boolean;
  snapshot?: (
    input: Parameters<AlertEvaluatorOrchestrationDependencies["readLifecycleSnapshot"]>[1],
  ) => AlertLifecycleSnapshot;
  terminalOutcome?: "committed" | "replayed";
}

interface HarnessEvents {
  boundAsOf: string[];
  failures: RecordAlertEvaluatorRunFailureInput[];
  persistInputs: PersistAlertLifecycleDecisionInput[];
  queueAsOf: string[];
  renewals: AlertEvaluatorRunFence[];
  sealedDecisions: AlertEvaluatorDecisionProofValue[][];
  sourceFences: AlertEvaluatorRunFence[];
  sourceProofs: AlertEvaluatorSourceProofValue[];
  successes: number;
  suppressed: AlertEvaluatorDecisionProofValue[];
}

function createHarness(options: HarnessOptions = {}): {
  dependencies: Partial<AlertEvaluatorOrchestrationDependencies>;
  events: HarnessEvents;
  run(queueProviders?: AlertEvaluatorQueueProviders): ReturnType<typeof runAlertEvaluator>;
} {
  const events: HarnessEvents = {
    boundAsOf: [],
    failures: [],
    persistInputs: [],
    queueAsOf: [],
    renewals: [],
    sealedDecisions: [],
    sourceFences: [],
    sourceProofs: [],
    successes: 0,
    suppressed: [],
  };
  let now = BASE_TIME;
  let persistAttempt = 0;
  const mutationOutcome = options.mutationOutcome ?? "committed";
  const proofOutcome = options.proofOutcome ?? "recorded";
  const terminalOutcome = options.terminalOutcome ?? "committed";
  const dependencies: Partial<AlertEvaluatorOrchestrationDependencies> = {
    async acquireRun(_database, input) {
      const fence: AlertEvaluatorRunFence = {
        leaseExpiresAt: new Date(
          Date.parse(input.startedAt) + (options.shortLease ? 100_000 : 600_000),
        ).toISOString(),
        leaseId: LEASE_ID,
        leaseRevision: 1,
        leaseUpdatedAt: input.startedAt,
        runId: RUN_ID,
        runtimeGeneration: 1,
        startedAt: input.startedAt,
      };
      return { fence, kind: "acquired", run: fakeRun(fence, "running") };
    },
    async bindRunAsOf(_database, fence, input) {
      events.boundAsOf.push(input.asOf);
      return {
        fence,
        kind: mutationOutcome,
        run: fakeRun(fence, "running", {
          asOf: input.asOf,
          updatedAt: input.boundAt,
        }),
      };
    },
    clock() {
      now += 1_000;
      return new Date(now);
    },
    async initializeRuntime() {
      return options.initialize ?? false;
    },
    async persistDecision(_database, input) {
      events.persistInputs.push(input);
      persistAttempt += 1;
      return options.persist ? options.persist(input, persistAttempt) : "applied";
    },
    async readAuditSource() {
      if (options.auditError) throw options.auditError;
      return options.auditResult ?? { incomplete: [], observations: [] };
    },
    async readFanoutSource() {
      return options.fanoutResult ?? { incomplete: [], observations: [] };
    },
    async readLifecycleSnapshot(_database, input) {
      return options.snapshot?.(input) ?? {
        expected: null,
        previous: inactiveAlertState(),
      };
    },
    async readLogoutSource() {
      return options.logoutResult ?? { incomplete: [], observations: [] };
    },
    async readOAuthSource() {
      return options.oauthResult ?? { incomplete: [], observations: [] };
    },
    async readQueueSource(_database, provider, input, clock) {
      const asOf = clock().toISOString();
      events.queueAsOf.push(asOf);
      try {
        await provider.metrics();
      } catch {
        return {
          observation: queueObservation(asOf, input.queueName),
          persistence: "unknown",
        };
      }
      return {
        observation: queueObservation(asOf, input.queueName),
        persistence: "committed",
      };
    },
    async readRuntimeSource() {
      return options.runtimeResult ?? { incomplete: [], observations: [] };
    },
    async recordFailure(_database, fence, input) {
      events.failures.push(input);
      if (options.recordFailureThrows) {
        throw new Error("simulated terminal response loss");
      }
      if (options.recordFailureLost) return { kind: "lost" };
      return {
        bootstrapCreated: false,
        kind: terminalOutcome,
        run: fakeRun(fence, "failed", {
          failureErrorCode: input.errorCode,
          failureStatus: input.status,
        }),
      };
    },
    async recordSource(_database, fence, input) {
      events.sourceFences.push(fence);
      events.sourceProofs.push(input.proof);
      return proofOutcome;
    },
    async recordSuccess(_database, fence) {
      events.successes += 1;
      return {
        bootstrapCreated: false,
        kind: terminalOutcome,
        run: fakeRun(fence, "succeeded"),
      };
    },
    async recordSuppressedDecision(_database, _fence, input) {
      events.suppressed.push(input.proof);
      return proofOutcome;
    },
    async renewRun(_database, fence, input) {
      events.renewals.push(fence);
      if (options.renewOutcome === "lost") return { kind: "lost" };
      const renewed: AlertEvaluatorRunFence = {
        ...fence,
        leaseExpiresAt: new Date(Date.parse(input.renewedAt) + 600_000)
          .toISOString(),
        leaseRevision: fence.leaseRevision + 1,
        leaseUpdatedAt: input.renewedAt,
      };
      return {
        fence: renewed,
        kind: options.renewOutcome ?? "committed",
        run: fakeRun(renewed, "running"),
      };
    },
    async sealRun(_database, fence, input) {
      events.sealedDecisions.push([...input.decisions]);
      return {
        fence,
        kind: mutationOutcome,
        run: fakeRun(fence, "sealed", { updatedAt: input.sealedAt }),
      };
    },
  };
  return {
    dependencies,
    events,
    run(queueProviders = healthyQueueProviders()) {
      return runAlertEvaluator({
        database: env.PG72_ID_DB,
        environment: "local",
        hmacKeyBase64Url: "H".repeat(43),
        mode: "observe_only",
        queueProviders,
        scheduledTime: BASE_TIME,
      }, dependencies);
    },
  };
}

interface D1QueryCounter {
  batches: number[];
  queries: number;
}

function countingDatabase(
  database: D1Database,
  counter: D1QueryCounter,
): D1Database {
  const rawStatements = new WeakMap<object, D1PreparedStatement>();
  const wrapStatement = (statement: D1PreparedStatement): D1PreparedStatement => {
    const proxy = new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) => wrapStatement(target.bind(...values));
        }
        if (
          property === "all" || property === "first" || property === "raw" ||
          property === "run"
        ) {
          const method: unknown = Reflect.get(target, property, target);
          if (typeof method !== "function") {
            throw new TypeError("invalid D1 prepared statement method");
          }
          return (...values: unknown[]) => {
            counter.queries += 1;
            return Reflect.apply(method, target, values);
          };
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    rawStatements.set(proxy, statement);
    return proxy;
  };
  return new Proxy(database, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => wrapStatement(target.prepare(query));
      }
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          counter.batches.push(statements.length);
          counter.queries += statements.length;
          return target.batch(statements.map((statement) =>
            rawStatements.get(statement) ?? statement
          ));
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

describe("alert evaluator orchestration", () => {
  it("pins the paid D1 statement budget and rejects Free-plan claims", () => {
    expect(ALERT_EVALUATOR_D1_QUERY_BUDGET.fixed).toEqual({
      acquireBindAndInitialize: 8,
      d1Sources: 32,
      queueSources: 12,
      runSourceProofs: 27,
      seal: 4,
      stageRenewals: 10,
      terminalWithFailureFallback: 17,
    });
    expect(ALERT_EVALUATOR_D1_QUERY_BUDGET.perWorkItem).toEqual({
      conflictRenewal: 2,
      initialLifecycleSnapshot: 2,
      initialPersistenceWithReadback: 15,
      recomputedLifecycleSnapshot: 2,
      retryPersistenceWithReadback: 15,
    });
    expect(ALERT_EVALUATOR_FIXED_D1_QUERY_BUDGET).toBe(110);
    expect(ALERT_EVALUATOR_PER_WORK_ITEM_D1_QUERY_BUDGET).toBe(36);
    expect(ALERT_EVALUATOR_MAX_WORK_ITEMS).toBe(20);
    expect(ALERT_EVALUATOR_MAX_WORK_ITEMS).toBeLessThan(25);
    const worstCase = ALERT_EVALUATOR_FIXED_D1_QUERY_BUDGET +
      ALERT_EVALUATOR_MAX_WORK_ITEMS *
        ALERT_EVALUATOR_PER_WORK_ITEM_D1_QUERY_BUDGET;
    expect(worstCase).toBe(830);
    expect(
      ALERT_EVALUATOR_D1_QUERY_BUDGET.paidInvocationLimit - worstCase,
    ).toBeGreaterThanOrEqual(
      ALERT_EVALUATOR_D1_QUERY_BUDGET.reservedPaidHeadroom,
    );
    expect(ALERT_EVALUATOR_FREE_PLAN_SUPPORTED).toBe(false);
  });

  it("initializes one tick without acquiring, sampling, or writing proof", async () => {
    let metricCalls = 0;
    const providers = healthyQueueProviders();
    for (const queue of ALERT_QUEUE_NAMES) {
      providers[queue] = { async metrics() { metricCalls += 1; return {}; } };
    }
    const harness = createHarness({ initialize: true });
    await expect(harness.run(providers)).resolves.toEqual({ kind: "initialized" });
    expect(metricCalls).toBe(0);
    expect(harness.events.sourceProofs).toEqual([]);
    expect(harness.events.successes).toBe(0);
  });

  it("keeps disabled mode free of clock, D1, and Queue work", async () => {
    let metricCalls = 0;
    const providers = healthyQueueProviders();
    for (const queue of ALERT_QUEUE_NAMES) {
      providers[queue] = { async metrics() { metricCalls += 1; return {}; } };
    }
    await expect(runAlertEvaluator({
      database: env.PG72_ID_DB,
      environment: "local",
      hmacKeyBase64Url: null,
      mode: "disabled",
      queueProviders: providers,
      scheduledTime: -1,
    }, {
      clock() {
        throw new Error("disabled mode must not read the clock");
      },
      async initializeRuntime() {
        throw new Error("disabled mode must not read D1");
      },
    })).resolves.toEqual({ kind: "disabled" });
    expect(metricCalls).toBe(0);
  });

  it("records the exact closed nine-source order", async () => {
    const harness = createHarness();
    await expect(harness.run()).resolves.toMatchObject({ kind: "succeeded" });
    expect(harness.events.sourceProofs.map(({ sourceId }) => sourceId)).toEqual(
      ALERT_EVALUATOR_SOURCE_IDS,
    );
    expect(harness.events.sourceProofs.every(({ status }) => status === "complete"))
      .toBe(true);
    expect(harness.events.successes).toBe(1);
    expect(harness.events.failures).toEqual([]);
  });

  it("starts all Queue reads together and binds one completion asOf", async () => {
    const resolvers = new Map<AlertQueueName, () => void>();
    const called: AlertQueueName[] = [];
    const delayedProvider = (queue: AlertQueueName) => ({
      metrics: () => new Promise<unknown>((resolve) => {
        called.push(queue);
        resolvers.set(queue, () => resolve({}));
      }),
    });
    const providers: AlertEvaluatorQueueProviders = {
      alert_deliveries_dlq: delayedProvider("alert_deliveries_dlq"),
      audit_archive_dlq: delayedProvider("audit_archive_dlq"),
      logout_deliveries_dlq: delayedProvider("logout_deliveries_dlq"),
      security_events_dlq: delayedProvider("security_events_dlq"),
    };
    const harness = createHarness();
    const pending = harness.run(providers);
    await vi.waitFor(() => expect(called).toHaveLength(4));
    for (const queue of ALERT_QUEUE_NAMES.slice(0, 3)) resolvers.get(queue)!();
    await Promise.resolve();
    expect(harness.events.boundAsOf).toEqual([]);
    resolvers.get(ALERT_QUEUE_NAMES[3])!();
    await expect(pending).resolves.toMatchObject({ kind: "succeeded" });
    expect(new Set(harness.events.queueAsOf)).toEqual(new Set([EXPECTED_AS_OF]));
    expect(harness.events.boundAsOf).toEqual([EXPECTED_AS_OF]);
    expect(harness.events.boundAsOf[0]).not.toBe(at(0));
  });

  it("completes a full run when every raw clock sample is the same millisecond", async () => {
    const harness = createHarness();
    harness.dependencies.clock = () => new Date(BASE_TIME + 1_000);
    await expect(harness.run()).resolves.toMatchObject({ kind: "succeeded" });
    expect(harness.events.boundAsOf).toEqual([at(1_001)]);
    expect(harness.events.sourceProofs).toHaveLength(9);
    expect(harness.events.persistInputs).toHaveLength(4);
    expect(harness.events.successes).toBe(1);
  });

  it("rejects a true raw clock reversal without losing terminal visibility", async () => {
    const samples = [BASE_TIME + 1_000, BASE_TIME + 999, BASE_TIME + 2_000];
    const harness = createHarness();
    harness.dependencies.clock = () => new Date(samples.shift() ?? BASE_TIME + 2_000);
    await expect(harness.run()).rejects.toEqual(
      new AlertEvaluatorOrchestrationError("clock_invalid"),
    );
    expect(harness.events.failures).toEqual([{
      completedAt: at(2_000),
      errorCode: "evaluator_failed",
      status: "failing",
    }]);
  });

  it("deduplicates before computing the source proof and planning", async () => {
    const observation = registrationObservation(EXPECTED_AS_OF, 5);
    const harness = createHarness({
      auditResult: { incomplete: [], observations: [observation, observation] },
    });
    await expect(harness.run()).resolves.toMatchObject({ kind: "succeeded" });
    const proof = harness.events.sourceProofs.find(
      ({ sourceId }) => sourceId === "d1.audit",
    );
    expect(proof).toMatchObject({ incompleteCount: 0, observationCount: 1 });
    expect(proof?.proofSha256).toBe(await canonicalAlertEvaluatorProofDigest(
      "source",
      {
        incomplete: [],
        observations: [observation],
        sourceId: "d1.audit",
        status: "complete",
      },
    ));
    expect(harness.events.persistInputs.filter(
      ({ runProof }) => runProof?.proof.sourceId === "d1.audit",
    )).toHaveLength(1);
  });

  it("reserves deterministic representation for every nonempty source", async () => {
    const audit = Array.from({ length: 25 }, (_, index) =>
      restrictedObservation(
        EXPECTED_AS_OF,
        `${String.fromCharCode(65 + index)}${"A".repeat(42)}`,
      )
    );
    const harness = createHarness({
      auditResult: { incomplete: [], observations: audit },
      fanoutResult: { incomplete: [], observations: [fanoutObservation(EXPECTED_AS_OF)] },
      logoutResult: { incomplete: [], observations: [logoutObservation(EXPECTED_AS_OF)] },
      oauthResult: { incomplete: [], observations: [oauthObservation(EXPECTED_AS_OF)] },
      runtimeResult: { incomplete: [], observations: [runtimeObservation(EXPECTED_AS_OF)] },
    });
    const failure = await harness.run().then(
      () => null,
      (error: unknown) => error,
    );
    expect(harness.events.sourceProofs.map(({ sourceId, status }) => ({
      sourceId,
      status,
    }))).toEqual(ALERT_EVALUATOR_SOURCE_IDS.map((sourceId) => ({
      sourceId,
      status: sourceId === "d1.audit" ? "partial" : "complete",
    })));
    const decisions = harness.events.sealedDecisions[0];
    expect(decisions).toHaveLength(ALERT_EVALUATOR_MAX_WORK_ITEMS);
    expect(new Set(decisions.map(({ sourceId }) => sourceId))).toEqual(
      new Set(ALERT_EVALUATOR_SOURCE_IDS),
    );
    const auditProof = harness.events.sourceProofs.find(
      ({ sourceId }) => sourceId === "d1.audit",
    );
    expect(auditProof).toMatchObject({
      incompleteCount: 13,
      observationCount: 25,
      status: "partial",
    });
    expect(harness.events.sourceProofs.filter(({ status }) => status === "partial"))
      .toHaveLength(1);
    expect(harness.events.failures).toEqual([{
      completedAt: expect.any(String),
      errorCode: "source_incomplete",
      status: "degraded",
    }]);
    expect(failure).toEqual(
      new AlertEvaluatorOrchestrationError("source_incomplete"),
    );
  });

  it("records partial clear only as suppressed proof without state mutation", async () => {
    const previous = activeWarningState();
    const before = JSON.stringify(previous);
    const harness = createHarness({
      auditResult: {
        incomplete: [{
          dimensionKind: "global",
          ruleId: "pgid.registration.rate_limited.v1",
        }],
        observations: [registrationObservation(EXPECTED_AS_OF, 0)],
      },
      snapshot: ({ ruleId }) => ruleId === "pgid.registration.rate_limited.v1"
        ? activeSnapshot(previous)
        : { expected: null, previous: inactiveAlertState() },
    });
    await expect(harness.run()).rejects.toMatchObject({ code: "source_incomplete" });
    expect(harness.events.suppressed).toHaveLength(1);
    expect(harness.events.suppressed[0]).toMatchObject({
      disposition: "suppressed_partial",
      sourceId: "d1.audit",
    });
    expect(harness.events.persistInputs.some(
      ({ runProof }) => runProof?.proof.sourceId === "d1.audit",
    )).toBe(false);
    expect(JSON.stringify(previous)).toBe(before);
  });

  it("allows retained partial evidence to escalate an active warning", async () => {
    const previous = pendingCriticalEscalationState();
    const harness = createHarness({
      auditResult: {
        incomplete: [{
          dimensionKind: "global",
          ruleId: "pgid.registration.rate_limited.v1",
        }],
        observations: [registrationObservation(EXPECTED_AS_OF, 40)],
      },
      snapshot: ({ ruleId }) => ruleId === "pgid.registration.rate_limited.v1"
        ? activeSnapshot(previous)
        : { expected: null, previous: inactiveAlertState() },
    });
    await expect(harness.run()).rejects.toMatchObject({ code: "source_incomplete" });
    const persisted = harness.events.persistInputs.find(
      ({ runProof }) => runProof?.proof.sourceId === "d1.audit",
    );
    expect(persisted?.decision.intent).toMatchObject({ kind: "escalate" });
    expect(persisted?.runProof?.proof.disposition).toBe("applied");
    expect(harness.events.suppressed).toEqual([]);
  });

  it.each([
    ["source_invalid", "invalid", "evaluator_failed", "failing"],
    ["source_unavailable", "unavailable", "metrics_unavailable", "unavailable"],
  ] as const)(
    "classifies D1 %s with the fixed terminal pair",
    async (repositoryCode, proofStatus, errorCode, failureStatus) => {
      const harness = createHarness({
        auditError: new AlertAuditSourceRepositoryError(repositoryCode),
      });
      await expect(harness.run()).rejects.toEqual(
        new AlertEvaluatorOrchestrationError(errorCode),
      );
      expect(harness.events.sourceProofs.find(
        ({ sourceId }) => sourceId === "d1.audit",
      )?.status).toBe(proofStatus);
      expect(harness.events.failures).toEqual([{
        completedAt: expect.any(String),
        errorCode,
        status: failureStatus,
      }]);
      expect(harness.events.successes).toBe(0);
    },
  );

  it("keeps clock precedence when source terminal time reverses before D1", async () => {
    let clockCall = 0;
    const harness = createHarness({
      auditError: new AlertAuditSourceRepositoryError("source_unavailable"),
    });
    harness.dependencies.clock = () => {
      clockCall += 1;
      return new Date(clockCall === 23
        ? BASE_TIME + 999
        : BASE_TIME + clockCall * 1_000);
    };
    await expect(harness.run()).rejects.toEqual(
      new AlertEvaluatorOrchestrationError("clock_invalid"),
    );
    expect(clockCall).toBe(24);
    expect(harness.events.failures).toEqual([{
      completedAt: at(24_000),
      errorCode: "evaluator_failed",
      status: "failing",
    }]);
  });

  it("renews a near-expiry lease and uses the returned fence", async () => {
    const harness = createHarness({ shortLease: true });
    await expect(harness.run()).resolves.toMatchObject({ kind: "succeeded" });
    expect(harness.events.renewals).toHaveLength(1);
    expect(harness.events.sourceFences.every(({ leaseRevision }) =>
      leaseRevision === 2
    )).toBe(true);
  });

  it("stops product writes without fabricating failure after lease loss", async () => {
    const harness = createHarness({ renewOutcome: "lost", shortLease: true });
    await expect(harness.run()).rejects.toEqual(
      new AlertEvaluatorOrchestrationError("lease_lost"),
    );
    expect(harness.events.renewals).toHaveLength(1);
    expect(harness.events.sourceProofs).toEqual([]);
    expect(harness.events.persistInputs).toEqual([]);
    expect(harness.events.failures).toEqual([]);
  });

  it("reports lease loss when failure terminalization loses ownership", async () => {
    const harness = createHarness({
      auditError: new AlertAuditSourceRepositoryError("source_unavailable"),
      recordFailureLost: true,
    });
    await expect(harness.run()).rejects.toEqual(
      new AlertEvaluatorOrchestrationError("lease_lost"),
    );
    expect(harness.events.failures).toHaveLength(1);
    expect(harness.events.successes).toBe(0);
  });

  it("makes one exact failure attempt when terminal readback is lost", async () => {
    const harness = createHarness({
      auditError: new AlertAuditSourceRepositoryError("source_unavailable"),
      recordFailureThrows: true,
    });
    await expect(harness.run()).rejects.toEqual(
      new AlertEvaluatorOrchestrationError("metrics_unavailable"),
    );
    expect(harness.events.failures).toHaveLength(1);
    expect(harness.events.successes).toBe(0);
  });

  it("accepts exact response-loss replay outcomes through terminal success", async () => {
    const harness = createHarness({
      mutationOutcome: "replayed",
      persist: () => "duplicate",
      proofOutcome: "replayed",
      terminalOutcome: "replayed",
    });
    await expect(harness.run()).resolves.toMatchObject({ kind: "succeeded" });
    expect(harness.events.sourceProofs).toHaveLength(9);
    expect(harness.events.persistInputs).toHaveLength(4);
    expect(harness.events.successes).toBe(1);
  });

  it("refreshes recordedAt after one proof-stable CAS recomputation", async () => {
    const attempts = new Map<number, number>();
    const harness = createHarness({
      persist(input) {
        const ordinal = input.runProof?.proof.ordinal ?? -1;
        const count = (attempts.get(ordinal) ?? 0) + 1;
        attempts.set(ordinal, count);
        return ordinal === 0 && count === 1 ? "conflict" : "applied";
      },
    });
    await expect(harness.run()).resolves.toMatchObject({ kind: "succeeded" });
    const first = harness.events.persistInputs.filter(
      ({ runProof }) => runProof?.proof.ordinal === 0,
    );
    expect(first).toHaveLength(2);
    expect(Date.parse(first[1].runProof!.recordedAt)).toBeGreaterThan(
      Date.parse(first[0].runProof!.recordedAt),
    );
    expect(first[1].runProof?.proof).toEqual(first[0].runProof?.proof);
  });

  it("terminalizes unexpected failures as failing and rethrows redacted", async () => {
    const harness = createHarness({
      persist() {
        throw new Error("sensitive provider detail");
      },
    });
    await expect(harness.run()).rejects.toEqual(
      new AlertEvaluatorOrchestrationError("evaluator_failed"),
    );
    expect(harness.events.failures).toEqual([{
      completedAt: expect.any(String),
      errorCode: "evaluator_failed",
      status: "failing",
    }]);
    expect(harness.events.successes).toBe(0);
  });

  it("classifies rejected Queue metrics as unavailable", async () => {
    const providers = healthyQueueProviders();
    providers.security_events_dlq = {
      async metrics() {
        throw new Error("provider detail");
      },
    };
    const harness = createHarness();
    await expect(harness.run(providers)).rejects.toEqual(
      new AlertEvaluatorOrchestrationError("metrics_unavailable"),
    );
    expect(harness.events.sourceProofs[0]).toMatchObject({
      sourceId: "queue.security_events_dlq",
      status: "unavailable",
    });
  });

  it("marks conflicting same-identity observations invalid", async () => {
    const harness = createHarness({
      auditResult: {
        incomplete: [],
        observations: [
          registrationObservation(EXPECTED_AS_OF, 5),
          registrationObservation(EXPECTED_AS_OF, 10),
        ],
      },
    });
    await expect(harness.run()).rejects.toEqual(
      new AlertEvaluatorOrchestrationError("evaluator_failed"),
    );
    expect(harness.events.sourceProofs.find(
      ({ sourceId }) => sourceId === "d1.audit",
    )).toMatchObject({ observationCount: 0, status: "invalid" });
  });

  it("uses code-point order rather than host locale order", async () => {
    const upper = `Z${"A".repeat(42)}`;
    const lower = `a${"A".repeat(42)}`;
    const harness = createHarness({
      auditResult: {
        incomplete: [],
        observations: [
          restrictedObservation(EXPECTED_AS_OF, lower),
          restrictedObservation(EXPECTED_AS_OF, upper),
        ],
      },
    });
    await expect(harness.run()).resolves.toMatchObject({ kind: "succeeded" });
    const auditDimensions = harness.events.persistInputs.flatMap(({ evaluation }) =>
      evaluation.ruleId === "pgid.restricted.sensitive_denied.v1" &&
          evaluation.dimension.kind === "subject_hmac"
        ? [evaluation.dimension.reference.value]
        : []
    );
    expect(auditDimensions).toEqual([upper, lower]);
  });

  it("executes the complete unwired local D1 proof path within budget", async () => {
    const fingerprint = await deriveAlertHashKeyFingerprintV1(TEST_HMAC_KEY);
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_hash_key_sentinel
        (id, domain, fingerprint_ref, hash_version, created_at)
       VALUES (1, ?, ?, 1, ?)`,
    ).bind(
      ALERT_HASH_KEY_SENTINEL_DOMAIN,
      fingerprint.value,
      at(-1_000),
    ).run();

    const counter: D1QueryCounter = { batches: [], queries: 0 };
    const database = countingDatabase(env.PG72_ID_DB, counter);
    const input = {
      database,
      environment: "local",
      hmacKeyBase64Url: TEST_HMAC_KEY,
      mode: "observe_only",
      queueProviders: {
        alert_deliveries_dlq: {
          async metrics() {
            return { backlogBytes: 0, backlogCount: 0 };
          },
        },
        audit_archive_dlq: {
          async metrics() {
            return { backlogBytes: 0, backlogCount: 0 };
          },
        },
        logout_deliveries_dlq: {
          async metrics() {
            return { backlogBytes: 0, backlogCount: 0 };
          },
        },
        security_events_dlq: {
          async metrics() {
            return { backlogBytes: 0, backlogCount: 0 };
          },
        },
      },
      scheduledTime: BASE_TIME,
    } as const;

    await expect(runAlertEvaluator(input, {
      clock: () => new Date(BASE_TIME + 1_000),
    })).resolves.toEqual({
      kind: "initialized",
    });
    expect(counter.queries).toBe(1);
    counter.batches = [];
    counter.queries = 0;

    const completed = await runAlertEvaluator(input, {
      // A real invocation makes many timestamped writes inside one wall-clock
      // millisecond; logical timestamps must advance without inventing reversal.
      clock: () => new Date(BASE_TIME + 2_000),
    });
    expect(completed.kind).toBe("succeeded");
    if (completed.kind !== "succeeded") throw new Error("expected success");
    const invocationQueries = counter.queries;
    expect(invocationQueries).toBe(80 + completed.run.decisionCount! * 4);
    expect(invocationQueries).toBeLessThanOrEqual(
      ALERT_EVALUATOR_FIXED_D1_QUERY_BUDGET +
        completed.run.decisionCount! *
          ALERT_EVALUATOR_PER_WORK_ITEM_D1_QUERY_BUDGET,
    );
    expect(invocationQueries).toBeLessThan(
      ALERT_EVALUATOR_D1_QUERY_BUDGET.paidInvocationLimit,
    );
    expect(counter.batches).toContain(15);
    expect(counter.batches).toContain(9);

    const sources = await env.PG72_ID_DB.prepare(
      `SELECT source_id, status FROM alert_evaluator_run_source
        WHERE run_id = ? ORDER BY source_id`,
    ).bind(completed.run.id).all<{ source_id: string; status: string }>();
    expect(sources.results).toHaveLength(9);
    expect(sources.results.every(({ status }) => status === "complete")).toBe(true);
    expect(await env.PG72_ID_DB.prepare(
      `SELECT status FROM alert_runtime_status WHERE component = 'evaluator'`,
    ).first("status")).toBe("healthy");
    expect(await env.PG72_ID_DB.prepare(
      `SELECT count(*) FROM alert_evaluator_bootstrap`,
    ).first("count(*)")).toBe(1);
  });
});
