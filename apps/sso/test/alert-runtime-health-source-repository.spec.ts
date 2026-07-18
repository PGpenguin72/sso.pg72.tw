import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import {
  advanceAlertLifecycle,
  inactiveAlertState,
} from "../worker/alert-evaluator";
import {
  ALERT_RUNTIME_HEALTH_OUTBOX_QUERY,
  AlertRuntimeHealthSourceRepositoryError,
  readRuntimeHealthAlertSource,
  type RuntimeHealthAlertSourceResult,
} from "../worker/alert-runtime-health-source-repository";
import {
  acquireAlertEvaluatorLease,
  initializeAlertEvaluatorRuntime,
  recordAlertEvaluatorSuccess,
} from "../worker/alert-runtime-repository";
import {
  evaluateAlertRule,
  ALERT_RUNTIME_SOURCE_QUERY,
  type AlertQueueName,
} from "../worker/alert-rules";
import {
  persistAlertLifecycleDecision,
  type AlertStateCasExpectation,
} from "../worker/alert-state-repository";

const AS_OF = "2032-07-18T02:00:00.000Z";

function at(base: string, offsetMilliseconds: number): string {
  return new Date(new Date(base).getTime() + offsetMilliseconds).toISOString();
}

async function read(
  asOf = AS_OF,
  database: D1Database = env.PG72_ID_DB,
): Promise<RuntimeHealthAlertSourceResult> {
  return readRuntimeHealthAlertSource(database, { asOf });
}

async function bootstrapEvaluator(
  firstSuccessAt = at(AS_OF, -10_000),
): Promise<string> {
  const existing = await env.PG72_ID_DB.prepare(
    `SELECT first_success_at
       FROM alert_evaluator_bootstrap
      WHERE component = 'evaluator'`,
  ).first<string>("first_success_at");
  if (existing !== null) return existing;
  const initializedAt = at(firstSuccessAt, -2_000);
  const startedAt = at(firstSuccessAt, -1_000);
  await initializeAlertEvaluatorRuntime(env.PG72_ID_DB, { initializedAt });
  const lease = await acquireAlertEvaluatorLease(env.PG72_ID_DB, {
    leaseDurationSeconds: 60,
    startedAt,
  });
  if (lease === null) throw new Error("expected evaluator lease");
  await recordAlertEvaluatorSuccess(env.PG72_ID_DB, lease, {
    completedAt: firstSuccessAt,
    watermarkAt: firstSuccessAt,
  });
  return firstSuccessAt;
}

function queueObservation(asOf: string, queue: AlertQueueName) {
  return {
    asOf,
    dimension: { kind: "queue", queue },
    ruleId: "pgid.queue.dlq_approximate.v1",
    snapshot: {
      backlogBytes: 1,
      backlogCount: 1,
      consecutiveNonzeroSamples: 1,
      nonzeroSinceAt: asOf,
      oldestMessageTimestamp: asOf,
      sampledAt: asOf,
    },
  } as const;
}

interface StateExpectationRow {
  generation: number;
  last_evaluated_at: string;
  revision: number;
  state_id: string;
}

async function createQueueOutbox(
  queue: AlertQueueName,
  firstAt: string,
  secondAt: string,
): Promise<number> {
  const firstObservation = queueObservation(firstAt, queue);
  const firstEvaluation = evaluateAlertRule(firstObservation);
  const firstDecision = advanceAlertLifecycle({
    asOf: firstAt,
    observation: firstObservation,
    previous: inactiveAlertState(),
  });
  expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, {
    decision: firstDecision,
    environment: "local",
    evaluation: firstEvaluation,
    expected: null,
  })).toBe("applied");
  const state = await env.PG72_ID_DB.prepare(
    `SELECT id AS state_id, generation, revision, last_evaluated_at
       FROM alert_state
      WHERE rule_id = 'pgid.queue.dlq_approximate.v1'
        AND queue_name = ?`,
  )
    .bind(queue)
    .first<StateExpectationRow>();
  if (state === null) throw new Error("expected Queue alert state");
  const expected: AlertStateCasExpectation = {
    generation: state.generation,
    incident: null,
    lastEvaluatedAt: state.last_evaluated_at,
    revision: state.revision,
    stateId: state.state_id,
  };
  const secondObservation = queueObservation(secondAt, queue);
  const secondEvaluation = evaluateAlertRule(secondObservation);
  const secondDecision = advanceAlertLifecycle({
    asOf: secondAt,
    observation: secondObservation,
    previous: firstDecision.state,
  });
  expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, {
    decision: secondDecision,
    environment: "local",
    evaluation: secondEvaluation,
    expected,
  })).toBe("applied");
  const outboxId = await env.PG72_ID_DB.prepare(
    `SELECT id FROM alert_outbox WHERE queue_name = ?`,
  )
    .bind(queue)
    .first<number>("id");
  if (outboxId === null) throw new Error("expected Queue alert outbox row");
  return outboxId;
}

interface ClaimedOutbox {
  attemptId: string;
  leaseId: string;
  outboxId: number;
}

async function claimOutbox(
  outboxId: number,
  claimedAt: string,
  leaseExpiresAt: string,
): Promise<ClaimedOutbox> {
  const leaseId = crypto.randomUUID();
  const attemptId = crypto.randomUUID();
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `UPDATE alert_outbox
          SET status = 'processing', attempts = attempts + 1,
              next_attempt_at = NULL, lease_id = ?, lease_expires_at = ?,
              updated_at = ?
        WHERE id = ?`,
    ).bind(leaseId, leaseExpiresAt, claimedAt, outboxId),
    env.PG72_ID_DB.prepare(
      `INSERT INTO alert_delivery_attempt
        (id, outbox_id, replay_count, attempt_number, lease_id, outcome,
         resulting_status, error_code, started_at, completed_at)
       VALUES (?, ?, 0, 1, ?, 'in_flight', 'processing', NULL, ?, NULL)`,
    ).bind(attemptId, outboxId, leaseId, claimedAt),
  ]);
  return { attemptId, leaseId, outboxId };
}

async function terminalizeOutbox(
  claim: ClaimedOutbox,
  status: "dead" | "retry",
  completedAt: string,
  nextAttemptAt: string | null,
): Promise<void> {
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `UPDATE alert_delivery_attempt
          SET outcome = ?, resulting_status = ?, error_code = 'network',
              completed_at = ?
        WHERE id = ?`,
    ).bind(status, status, completedAt, claim.attemptId),
    env.PG72_ID_DB.prepare(
      `UPDATE alert_outbox
          SET status = ?, next_attempt_at = ?, lease_id = NULL,
              lease_expires_at = NULL, dead_at = ?,
              last_error_code = 'network', updated_at = ?
        WHERE id = ?`,
    ).bind(
      status,
      nextAttemptAt,
      status === "dead" ? completedAt : null,
      completedAt,
      claim.outboxId,
    ),
  ]);
}

function transformBatchDatabase(
  transform: (
    results: D1Result<Record<string, unknown>>[],
  ) => D1Result<Record<string, unknown>>[],
): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) =>
          transform(
            await target.batch<Record<string, unknown>>(statements),
          );
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function replaceResultRows(
  results: D1Result<Record<string, unknown>>[],
  index: number,
  rows: readonly Record<string, unknown>[],
): D1Result<Record<string, unknown>>[] {
  return results.map((result, resultIndex) =>
    resultIndex === index ? { ...result, results: [...rows] } : result
  );
}

function transformOutboxRow(
  transform: (row: Record<string, unknown>) => Record<string, unknown>,
): D1Database {
  return transformBatchDatabase((results) => {
    const row = results[1]?.results?.[0];
    if (typeof row !== "object" || row === null || Array.isArray(row)) {
      throw new Error("expected real outbox projection");
    }
    return replaceResultRows(results, 1, [transform(row)]);
  });
}

function failingBatchDatabase(): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return async () => {
          throw new Error("sensitive-detail-must-not-leak");
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

describe.sequential("runtime-health alert source repository", () => {
  beforeEach(async () => {
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare("DELETE FROM alert_delivery_attempt"),
      env.PG72_ID_DB.prepare("DELETE FROM alert_outbox"),
      env.PG72_ID_DB.prepare("DELETE FROM security_alert"),
      env.PG72_ID_DB.prepare("DELETE FROM alert_state"),
    ]);
  });

  it("excludes the whole rule before immutable evaluator bootstrap", async () => {
    const outboxId = await createQueueOutbox(
      "alert_deliveries_dlq",
      at(AS_OF, -2_000),
      at(AS_OF, -1_000),
    );
    const claim = await claimOutbox(
      outboxId,
      AS_OF,
      at(AS_OF, 30_000),
    );
    await terminalizeOutbox(
      claim,
      "dead",
      at(AS_OF, 1_000),
      null,
    );
    await expect(read(at(AS_OF, 2_000))).resolves.toEqual({
      incomplete: [],
      observations: [],
    });
  });

  it("emits a complete empty-outbox observation after first success", async () => {
    await bootstrapEvaluator();
    const result = await read();
    expect(result).toEqual({
      incomplete: [],
      observations: [{
        asOf: AS_OF,
        dimension: { kind: "global" },
        ruleId: "pgid.alert.runtime_health.v1",
        snapshot: {
          deadOutbox: 0,
          evaluatorAgeSeconds: 10,
          outboxDueAgeSeconds: null,
        },
      }],
    });
    expect(evaluateAlertRule(result.observations[0])).toMatchObject({
      evidence: "known",
      severity: "none",
    });
  });

  it("reads all-age dead work and the oldest due or expired clock", async () => {
    const firstSuccessAt = await bootstrapEvaluator(at(AS_OF, -5_000));
    const deadId = await createQueueOutbox(
      "security_events_dlq",
      at(AS_OF, -7_300_000),
      at(AS_OF, -7_200_000),
    );
    const deadClaim = await claimOutbox(
      deadId,
      at(AS_OF, -7_190_000),
      at(AS_OF, -7_000_000),
    );
    await terminalizeOutbox(
      deadClaim,
      "dead",
      at(AS_OF, -7_100_000),
      null,
    );

    const processingId = await createQueueOutbox(
      "logout_deliveries_dlq",
      at(AS_OF, -1_300_000),
      at(AS_OF, -1_200_000),
    );
    await claimOutbox(
      processingId,
      at(AS_OF, -1_190_000),
      at(AS_OF, -600_000),
    );

    const retryId = await createQueueOutbox(
      "audit_archive_dlq",
      at(AS_OF, -500_000),
      at(AS_OF, -400_000),
    );
    const retryClaim = await claimOutbox(
      retryId,
      at(AS_OF, -390_000),
      at(AS_OF, -300_000),
    );
    await terminalizeOutbox(
      retryClaim,
      "retry",
      at(AS_OF, -350_000),
      at(AS_OF, -200_000),
    );

    const result = await read();
    expect(result.incomplete).toEqual([]);
    expect(result.observations[0]?.snapshot).toEqual({
      deadOutbox: 1,
      evaluatorAgeSeconds: Math.floor(
        (new Date(AS_OF).getTime() - new Date(firstSuccessAt).getTime()) / 1_000,
      ),
      outboxDueAgeSeconds: 600,
    });
    expect(evaluateAlertRule(result.observations[0])).toMatchObject({
      immediateCritical: true,
      severity: "critical",
    });
  });

  it("includes exact due/expiry boundaries and excludes future work", async () => {
    await bootstrapEvaluator(at(AS_OF, -1_000));
    await createQueueOutbox(
      "alert_deliveries_dlq",
      at(AS_OF, -1_000),
      AS_OF,
    );
    await createQueueOutbox(
      "audit_archive_dlq",
      at(AS_OF, 1_000),
      at(AS_OF, 2_000),
    );
    const processingId = await createQueueOutbox(
      "logout_deliveries_dlq",
      at(AS_OF, -5_000),
      at(AS_OF, -4_000),
    );
    await claimOutbox(
      processingId,
      at(AS_OF, -3_000),
      AS_OF,
    );
    const result = await read();
    expect(result.observations[0]?.snapshot.outboxDueAgeSeconds).toBe(0);
  });

  it("preserves post-bootstrap evaluator-missing semantics", async () => {
    await bootstrapEvaluator();
    const missingRuntime = transformBatchDatabase((results) => {
      const row = results[0]?.results?.[0];
      if (typeof row !== "object" || row === null || Array.isArray(row)) {
        throw new Error("expected runtime projection");
      }
      return replaceResultRows(results, 0, [{
        ...row,
        runtime_component: null,
        runtime_generation: null,
        runtime_last_error_at: null,
        runtime_last_error_code: null,
        runtime_last_started_at: null,
        runtime_last_success_at: null,
        runtime_revision: null,
        runtime_status: null,
        runtime_updated_at: null,
      }]);
    });
    const result = await read(AS_OF, missingRuntime);
    expect(result.observations[0]?.snapshot).toEqual({
      deadOutbox: 0,
      evaluatorAgeSeconds: null,
      outboxDueAgeSeconds: null,
    });
    expect(evaluateAlertRule(result.observations[0])).toMatchObject({
      immediateCritical: true,
      severity: "critical",
    });
  });

  it("marks bounded evidence overflow incomplete without manufacturing a clear", async () => {
    await bootstrapEvaluator();
    for (const database of [
      transformOutboxRow((row) => ({
        ...row,
        dead_outbox: 1_000_000_001,
      })),
      transformOutboxRow((row) => ({
        ...row,
        pending_retry_due_count: 1_000_000_001,
        pending_retry_oldest_due_at: AS_OF,
        pending_retry_newest_due_at: AS_OF,
      })),
      transformOutboxRow((row) => ({
        ...row,
        pending_retry_due_count: 1,
        pending_retry_oldest_due_at: "0001-01-01T00:00:00.000Z",
        pending_retry_newest_due_at: "0001-01-01T00:00:00.000Z",
      })),
      transformOutboxRow((row) => ({
        ...row,
        pending_retry_due_count: 600_000_000,
        pending_retry_oldest_due_at: AS_OF,
        pending_retry_newest_due_at: AS_OF,
        processing_due_count: 600_000_000,
        processing_oldest_due_at: AS_OF,
        processing_newest_due_at: AS_OF,
      })),
    ]) {
      await expect(read(AS_OF, database)).resolves.toEqual({
        incomplete: [{
          dimensionKind: "global",
          ruleId: "pgid.alert.runtime_health.v1",
        }],
        observations: [],
      });
    }
  });

  it("rejects malformed result shapes, counts, and due chronology", async () => {
    await bootstrapEvaluator();
    const corruptDatabases = [
      transformBatchDatabase(() => []),
      transformBatchDatabase((results) => {
        const row = results[0]?.results?.[0];
        if (typeof row !== "object" || row === null || Array.isArray(row)) {
          throw new Error("expected runtime projection");
        }
        return replaceResultRows(results, 0, [{
          ...row,
          unexpected_sensitive_field: "must-not-leak",
        }]);
      }),
      transformBatchDatabase((results) => replaceResultRows(results, 1, [])),
      transformBatchDatabase((results) => {
        const rows = results[1]?.results ?? [];
        return replaceResultRows(results, 1, [...rows, ...rows]);
      }),
      transformOutboxRow((row) => ({
        ...row,
        unexpected_sensitive_field: "must-not-leak",
      })),
      transformOutboxRow((row) => {
        const { dead_outbox: _omitted, ...rest } = row;
        return rest;
      }),
      transformOutboxRow((row) => ({ ...row, dead_outbox: -1 })),
      transformOutboxRow((row) => ({ ...row, dead_outbox: 0.5 })),
      transformOutboxRow((row) => ({
        ...row,
        pending_retry_due_count: 0,
        pending_retry_oldest_due_at: AS_OF,
      })),
      transformOutboxRow((row) => ({
        ...row,
        pending_retry_due_count: 1,
        pending_retry_oldest_due_at: null,
        pending_retry_newest_due_at: null,
      })),
      transformOutboxRow((row) => ({
        ...row,
        pending_retry_due_count: 1,
        pending_retry_oldest_due_at: "not-a-time",
        pending_retry_newest_due_at: "not-a-time",
      })),
      transformOutboxRow((row) => ({
        ...row,
        pending_retry_due_count: 1,
        pending_retry_oldest_due_at: at(AS_OF, 2_000),
        pending_retry_newest_due_at: at(AS_OF, 1_000),
      })),
      transformOutboxRow((row) => ({
        ...row,
        pending_retry_due_count: 1,
        pending_retry_oldest_due_at: at(AS_OF, 1_000),
        pending_retry_newest_due_at: at(AS_OF, 1_000),
      })),
      transformBatchDatabase((results) =>
        results.map((result, index) =>
          index === 1
            ? { ...result, success: false } as unknown as D1Result<
              Record<string, unknown>
            >
            : result
        )
      ),
    ];
    for (const database of corruptDatabases) {
      const failure = read(AS_OF, database);
      await expect(failure).rejects.toEqual(
        new AlertRuntimeHealthSourceRepositoryError("source_invalid"),
      );
      await expect(failure).rejects.not.toThrow("must-not-leak");
    }
  });

  it("redacts invalid input and D1 execution failures", async () => {
    const invalid = read("private-payload-invalid-time");
    await expect(invalid).rejects.toEqual(
      new AlertRuntimeHealthSourceRepositoryError("invalid_input"),
    );
    await expect(invalid).rejects.not.toThrow("private-payload");
    const unavailable = read(AS_OF, failingBatchDatabase());
    await expect(unavailable).rejects.toEqual(
      new AlertRuntimeHealthSourceRepositoryError("source_unavailable"),
    );
    await expect(unavailable).rejects.not.toThrow("sensitive-detail");
  });

  it("uses one exact two-statement D1 batch", async () => {
    const prepared: string[] = [];
    let batches = 0;
    const database = new Proxy(env.PG72_ID_DB, {
      get(target, property) {
        if (property === "prepare") {
          return (query: string) => {
            prepared.push(query);
            return target.prepare(query);
          };
        }
        if (property === "batch") {
          return async (statements: D1PreparedStatement[]) => {
            batches += 1;
            return target.batch<Record<string, unknown>>(statements);
          };
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    await read(AS_OF, database);
    expect(batches).toBe(1);
    expect(prepared).toEqual([
      ALERT_RUNTIME_SOURCE_QUERY,
      ALERT_RUNTIME_HEALTH_OUTBOX_QUERY,
    ]);
  });

  it("pins every all-age outbox path to the existing covering index", async () => {
    const plan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN ${ALERT_RUNTIME_HEALTH_OUTBOX_QUERY}`,
    )
      .bind(AS_OF)
      .all<{ detail: string }>();
    const details = plan.results.map(({ detail }) => detail).join("\n");
    expect(details.match(/alert_outbox_due_idx/g)).toHaveLength(3);
    expect(details).not.toMatch(/SCAN alert_outbox(?:\s|$)/);
    expect(ALERT_RUNTIME_HEALTH_OUTBOX_QUERY).not.toMatch(
      /alert_id|client_id|dedupe_key|email|idempotency|payload|subject_ref|user/i,
    );
  });
});
