import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import {
  advanceAlertLifecycle,
  inactiveAlertState,
} from "../worker/alert-evaluator";
import {
  acquireAlertEvaluatorRun,
  bindAlertEvaluatorRunAsOf,
  recordAlertEvaluatorRunSource,
  recordAlertEvaluatorRunSuccess,
  sealAlertEvaluatorRunPlan,
  type AlertEvaluatorRunFence,
} from "../worker/alert-run-repository";
import {
  ALERT_EVALUATOR_SOURCE_IDS,
  type AlertEvaluatorDecisionProofValue,
} from "../worker/alert-run-proof";
import { initializeAlertEvaluatorRuntime } from "../worker/alert-runtime-repository";
import {
  persistAlertLifecycleDecision,
  readAlertLifecycleSnapshot,
} from "../worker/alert-state-repository";
import { evaluateAlertRule } from "../worker/alert-rules";

const DIGEST = "A".repeat(43);
const GLOBAL = { kind: "global" } as const;

function at(seconds: number): string {
  return new Date(Date.parse("2026-07-18T00:00:00.000Z") + seconds * 1_000)
    .toISOString();
}

function observation(asOf: string, count: number) {
  return {
    asOf,
    dimension: GLOBAL,
    ruleId: "pgid.registration.rate_limited.v1",
    windows: {
      "5m": { count },
      "15m": { count },
      "60m": { count },
    },
  } as const;
}

function appliedPlan(): AlertEvaluatorDecisionProofValue & {
  disposition: "applied";
} {
  return {
    decisionSha256: `I${"A".repeat(42)}`,
    disposition: "applied",
    evaluationSha256: `E${"A".repeat(42)}`,
    identitySha256: DIGEST,
    ordinal: 0,
    sourceId: "d1.audit",
  };
}

function noStatePlan(): AlertEvaluatorDecisionProofValue & {
  disposition: "no_state_change";
} {
  return {
    ...appliedPlan(),
    disposition: "no_state_change",
  };
}

function immediatePlan(): AlertEvaluatorDecisionProofValue & {
  disposition: "applied";
} {
  return {
    decisionSha256: `U${"A".repeat(42)}`,
    disposition: "applied",
    evaluationSha256: `Y${"A".repeat(42)}`,
    identitySha256: `Q${"A".repeat(42)}`,
    ordinal: 0,
    sourceId: "d1.alert_runtime",
  };
}

async function reset(): Promise<void> {
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      "DROP TRIGGER IF EXISTS alert_runtime_evaluator_lease_run_guard",
    ),
    env.PG72_ID_DB.prepare(
      "DROP TRIGGER IF EXISTS alert_runtime_evaluator_idle_update_guard",
    ),
    env.PG72_ID_DB.prepare(
      "DROP TRIGGER IF EXISTS alert_runtime_evaluator_terminal_run_guard",
    ),
    env.PG72_ID_DB.prepare(
      "DROP TRIGGER IF EXISTS alert_runtime_evaluator_terminalize_run",
    ),
    env.PG72_ID_DB.prepare(
      "DROP TRIGGER IF EXISTS alert_evaluator_bootstrap_insert_guard",
    ),
    env.PG72_ID_DB.prepare(
      "DROP TRIGGER IF EXISTS alert_evaluator_bootstrap_update_guard",
    ),
    env.PG72_ID_DB.prepare(
      "DROP TRIGGER IF EXISTS alert_evaluator_bootstrap_delete_guard",
    ),
    env.PG72_ID_DB.prepare("DROP TABLE IF EXISTS alert_evaluator_run_decision"),
    env.PG72_ID_DB.prepare("DROP TABLE IF EXISTS alert_evaluator_run_source"),
    env.PG72_ID_DB.prepare("DROP TABLE IF EXISTS alert_evaluator_run"),
    env.PG72_ID_DB.prepare("DELETE FROM alert_delivery_attempt"),
    env.PG72_ID_DB.prepare("DELETE FROM alert_outbox"),
    env.PG72_ID_DB.prepare("DELETE FROM security_alert"),
    env.PG72_ID_DB.prepare("DELETE FROM alert_state"),
    env.PG72_ID_DB.prepare("DELETE FROM alert_evaluator_bootstrap"),
    env.PG72_ID_DB.prepare("DELETE FROM alert_runtime_status"),
  ]);
  const observability = env.TEST_MIGRATIONS.find(
    ({ name }) => name === "0020_alert_observability.sql",
  );
  const proofMigration = env.TEST_MIGRATIONS.find(
    ({ name }) => name === "0022_alert_evaluator_run_proof.sql",
  );
  if (!observability || !proofMigration) throw new Error("missing alert migration");
  const bootstrapTriggers = observability.queries.filter((query) =>
    query.includes('CREATE TRIGGER "alert_evaluator_bootstrap_')
  );
  await env.PG72_ID_DB.batch([
    ...bootstrapTriggers.map((query) => env.PG72_ID_DB.prepare(query)),
    ...proofMigration.queries.map((query) => env.PG72_ID_DB.prepare(query)),
  ]);
}

async function setupRun(
  plan: AlertEvaluatorDecisionProofValue,
): Promise<AlertEvaluatorRunFence> {
  await initializeAlertEvaluatorRuntime(env.PG72_ID_DB, { initializedAt: at(0) });
  const acquired = await acquireAlertEvaluatorRun(env.PG72_ID_DB, {
    leaseDurationSeconds: 180,
    scheduledAt: at(60),
    startedAt: at(60),
    triggerCron: "* * * * *",
  });
  if (!acquired || acquired.kind !== "acquired") throw new Error("expected run");
  const fence = acquired.fence;
  await bindAlertEvaluatorRunAsOf(env.PG72_ID_DB, fence, {
    asOf: at(70),
    boundAt: at(70),
  });
  for (const sourceId of ALERT_EVALUATOR_SOURCE_IDS) {
    await recordAlertEvaluatorRunSource(env.PG72_ID_DB, fence, {
      asOf: at(70),
      proof: {
        incompleteCount: 0,
        observationCount: 1,
        proofSha256: DIGEST,
        sourceId,
        status: "complete",
      },
      recordedAt: at(71),
    });
  }
  await sealAlertEvaluatorRunPlan(env.PG72_ID_DB, fence, {
    decisions: [plan],
    sealedAt: at(72),
  });
  return fence;
}

function stateBatchThenThrowOnce(): D1Database {
  let first = true;
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          const results = await target.batch(statements);
          if (first) {
            first = false;
            throw new Error("simulated state response loss");
          }
          return results;
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function mismatchedProofStateDatabase(): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          const results = await target.batch(statements);
          const proof = results.at(-1)?.results[0];
          if (
            typeof proof !== "object" || proof === null ||
            !("state_id" in proof)
          ) {
            throw new Error("expected proof projection");
          }
          results.at(-1)!.results[0] = {
            ...(proof as Record<string, unknown>),
            state_id: crypto.randomUUID(),
          };
          return results;
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function pendingDecision() {
  const source = observation(at(70), 5);
  const evaluation = evaluateAlertRule(source);
  const decision = advanceAlertLifecycle({
    asOf: at(70),
    observation: source,
    previous: inactiveAlertState(),
  });
  return { decision, evaluation };
}

function immediateDecision() {
  const source = {
    asOf: at(70),
    dimension: GLOBAL,
    ruleId: "pgid.alert.runtime_health.v1",
    snapshot: {
      deadOutbox: 1,
      evaluatorAgeSeconds: 0,
      outboxDueAgeSeconds: null,
    },
  } as const;
  const evaluation = evaluateAlertRule(source);
  const decision = advanceAlertLifecycle({
    asOf: at(70),
    observation: source,
    previous: inactiveAlertState(),
  });
  return { decision, evaluation };
}

async function persistLegacyState(): Promise<void> {
  const source = observation(at(69), 5);
  const evaluation = evaluateAlertRule(source);
  const decision = advanceAlertLifecycle({
    asOf: at(69),
    observation: source,
    previous: inactiveAlertState(),
  });
  expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, {
    decision,
    environment: "local",
    evaluation,
    expected: null,
  })).toBe("applied");
}

describe("alert state evaluator-run proof", () => {
  beforeEach(reset);

  it("commits state and immutable proof together and replays exactly", async () => {
    const plan = appliedPlan();
    const fence = await setupRun(plan);
    const { decision, evaluation } = pendingDecision();
    const input = {
      decision,
      environment: "local" as const,
      evaluation,
      expected: null,
      runProof: { fence, proof: plan, recordedAt: at(73) },
    };
    expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, input)).toBe(
      "applied",
    );
    expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, input)).toBe(
      "duplicate",
    );
    const state = await env.PG72_ID_DB.prepare(
      "SELECT id, generation, revision FROM alert_state",
    ).first<{ generation: number; id: string; revision: number }>();
    expect(state).not.toBeNull();
    expect(await env.PG72_ID_DB.prepare(
      `SELECT state_id, state_generation, state_revision, disposition
         FROM alert_evaluator_run_decision`,
    ).first()).toEqual({
      disposition: "applied",
      state_generation: state?.generation,
      state_id: state?.id,
      state_revision: state?.revision,
    });
    expect(await recordAlertEvaluatorRunSuccess(env.PG72_ID_DB, fence, {
      completedAt: at(74),
    })).toMatchObject({ kind: "committed", run: { status: "succeeded" } });
  });

  it("recovers an execute-after-commit state batch response", async () => {
    const plan = appliedPlan();
    const fence = await setupRun(plan);
    const { decision, evaluation } = pendingDecision();
    expect(await persistAlertLifecycleDecision(stateBatchThenThrowOnce(), {
      decision,
      environment: "local",
      evaluation,
      expected: null,
      runProof: { fence, proof: plan, recordedAt: at(73) },
    })).toBe("applied");
    expect(await env.PG72_ID_DB.prepare(
      "SELECT count(*) AS count FROM alert_evaluator_run_decision",
    ).first("count")).toBe(1);
  });

  it("commits and exactly replays the full immediate incident chain", async () => {
    const plan = immediatePlan();
    const fence = await setupRun(plan);
    const { decision, evaluation } = immediateDecision();
    const input = {
      decision,
      environment: "local" as const,
      evaluation,
      expected: null,
      runProof: { fence, proof: plan, recordedAt: at(73) },
    };
    expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, input)).toBe(
      "applied",
    );
    expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, input)).toBe(
      "duplicate",
    );
    const counts = await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare("SELECT count(*) AS count FROM alert_state"),
      env.PG72_ID_DB.prepare("SELECT count(*) AS count FROM security_alert"),
      env.PG72_ID_DB.prepare("SELECT count(*) AS count FROM alert_outbox"),
      env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM alert_evaluator_run_decision",
      ),
    ]);
    expect(counts.map((result) => result.results[0])).toEqual([
      { count: 1 },
      { count: 1 },
      { count: 1 },
      { count: 1 },
    ]);
    expect(await env.PG72_ID_DB.prepare(
      `SELECT state_generation, state_revision, disposition
         FROM alert_evaluator_run_decision`,
    ).first()).toEqual({
      disposition: "applied",
      state_generation: 1,
      state_revision: 1,
    });
  });

  it("rolls the full immediate incident chain back for a stale fence", async () => {
    const plan = immediatePlan();
    const fence = await setupRun(plan);
    expect(await acquireAlertEvaluatorRun(env.PG72_ID_DB, {
      leaseDurationSeconds: 180,
      scheduledAt: at(240),
      startedAt: at(240),
      triggerCron: "* * * * *",
    })).toMatchObject({ kind: "acquired" });
    const { decision, evaluation } = immediateDecision();
    expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, {
      decision,
      environment: "local",
      evaluation,
      expected: null,
      runProof: { fence, proof: plan, recordedAt: at(73) },
    })).toBe("conflict");
    const counts = await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare("SELECT count(*) AS count FROM alert_state"),
      env.PG72_ID_DB.prepare("SELECT count(*) AS count FROM security_alert"),
      env.PG72_ID_DB.prepare("SELECT count(*) AS count FROM alert_outbox"),
      env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM alert_evaluator_run_decision",
      ),
    ]);
    expect(counts.map((result) => result.results[0])).toEqual([
      { count: 0 },
      { count: 0 },
      { count: 0 },
      { count: 0 },
    ]);
  });

  it("does not mint proof when the product CAS changes zero rows", async () => {
    await persistLegacyState();
    const plan = appliedPlan();
    const fence = await setupRun(plan);
    const { decision, evaluation } = pendingDecision();
    expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, {
      decision,
      environment: "local",
      evaluation,
      expected: null,
      runProof: { fence, proof: plan, recordedAt: at(73) },
    })).toBe("conflict");
    expect(await env.PG72_ID_DB.prepare(
      "SELECT count(*) AS count FROM alert_evaluator_run_decision",
    ).first("count")).toBe(0);
  });

  it("lets one concurrent state+proof writer win without retroactive proof", async () => {
    const plan = appliedPlan();
    const fence = await setupRun(plan);
    const { decision, evaluation } = pendingDecision();
    const input = {
      decision,
      environment: "local" as const,
      evaluation,
      expected: null,
      runProof: { fence, proof: plan, recordedAt: at(73) },
    };
    expect((await Promise.all([
      persistAlertLifecycleDecision(env.PG72_ID_DB, input),
      persistAlertLifecycleDecision(env.PG72_ID_DB, input),
    ])).toSorted()).toEqual(["applied", "duplicate"]);
    expect(await env.PG72_ID_DB.prepare(
      "SELECT count(*) AS count FROM alert_evaluator_run_decision",
    ).first("count")).toBe(1);
  });

  it("rejects proof coordinates that do not identify the readback state", async () => {
    const plan = appliedPlan();
    const fence = await setupRun(plan);
    const { decision, evaluation } = pendingDecision();
    const input = {
      decision,
      environment: "local" as const,
      evaluation,
      expected: null,
      runProof: { fence, proof: plan, recordedAt: at(73) },
    };
    expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, input)).toBe(
      "applied",
    );
    expect(await persistAlertLifecycleDecision(
      mismatchedProofStateDatabase(),
      input,
    )).toBe("conflict");
  });

  it("proves no-state only while the semantic state is absent", async () => {
    const plan = noStatePlan();
    const fence = await setupRun(plan);
    const source = observation(at(70), 0);
    const evaluation = evaluateAlertRule(source);
    const decision = advanceAlertLifecycle({
      asOf: at(70),
      observation: source,
      previous: inactiveAlertState(),
    });
    const input = {
      decision,
      environment: "local" as const,
      evaluation,
      expected: null,
      runProof: { fence, proof: plan, recordedAt: at(73) },
    };
    expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, input)).toBe(
      "applied",
    );
    expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, input)).toBe(
      "duplicate",
    );
    expect(await readAlertLifecycleSnapshot(env.PG72_ID_DB, {
      dimension: GLOBAL,
      environment: "local",
      ruleId: "pgid.registration.rate_limited.v1",
    })).toEqual({ expected: null, previous: inactiveAlertState() });
  });

  it("rejects no-state proof when a semantic state already exists", async () => {
    await persistLegacyState();
    const plan = noStatePlan();
    const fence = await setupRun(plan);
    const source = observation(at(70), 0);
    const evaluation = evaluateAlertRule(source);
    const decision = advanceAlertLifecycle({
      asOf: at(70),
      observation: source,
      previous: inactiveAlertState(),
    });
    expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, {
      decision,
      environment: "local",
      evaluation,
      expected: null,
      runProof: { fence, proof: plan, recordedAt: at(73) },
    })).toBe("conflict");
    expect(await env.PG72_ID_DB.prepare(
      "SELECT count(*) AS count FROM alert_evaluator_run_decision",
    ).first("count")).toBe(0);
  });

  it("lets an expired owner write neither state nor proof", async () => {
    const plan = appliedPlan();
    const fence = await setupRun(plan);
    const takeover = await acquireAlertEvaluatorRun(env.PG72_ID_DB, {
      leaseDurationSeconds: 180,
      scheduledAt: at(240),
      startedAt: at(240),
      triggerCron: "* * * * *",
    });
    expect(takeover).toMatchObject({ kind: "acquired" });
    const { decision, evaluation } = pendingDecision();
    expect(await persistAlertLifecycleDecision(env.PG72_ID_DB, {
      decision,
      environment: "local",
      evaluation,
      expected: null,
      runProof: { fence, proof: plan, recordedAt: at(73) },
    })).toBe("conflict");
    expect(await env.PG72_ID_DB.prepare(
      "SELECT count(*) AS count FROM alert_state",
    ).first("count")).toBe(0);
    expect(await env.PG72_ID_DB.prepare(
      "SELECT count(*) AS count FROM alert_evaluator_run_decision",
    ).first("count")).toBe(0);
  });
});
