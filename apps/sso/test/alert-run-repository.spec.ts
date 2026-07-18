import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import {
  acquireAlertEvaluatorRun,
  AlertRunRepositoryError,
  bindAlertEvaluatorRunAsOf,
  readAlertEvaluatorRun,
  recordNoStateChangeAlertEvaluatorDecision,
  recordAlertEvaluatorRunFailure,
  recordAlertEvaluatorRunSource,
  recordAlertEvaluatorRunSuccess,
  recordSuppressedAlertEvaluatorDecision,
  renewAlertEvaluatorRun,
  sealAlertEvaluatorRunPlan,
  type AlertEvaluatorRunFence,
} from "../worker/alert-run-repository";
import {
  ALERT_EVALUATOR_SOURCE_IDS,
  type AlertEvaluatorDecisionProofValue,
  type AlertEvaluatorSourceId,
  type AlertEvaluatorSourceProofValue,
} from "../worker/alert-run-proof";
import { initializeAlertEvaluatorRuntime } from "../worker/alert-runtime-repository";

const DIGEST = "A".repeat(43);

function at(seconds: number): string {
  return new Date(Date.parse("2026-07-18T00:00:00.000Z") + seconds * 1_000)
    .toISOString();
}

function atMilliseconds(milliseconds: number): string {
  return new Date(
    Date.parse("2026-07-18T00:00:00.000Z") + milliseconds,
  ).toISOString();
}

function proof(
  sourceId: AlertEvaluatorSourceId,
  status: AlertEvaluatorSourceProofValue["status"] = "complete",
): AlertEvaluatorSourceProofValue {
  return {
    incompleteCount: status === "partial" ? 1 : 0,
    observationCount: status === "unavailable" || status === "invalid" ? 0 : 1,
    proofSha256: DIGEST,
    sourceId,
    status,
  };
}

function decision(
  disposition: AlertEvaluatorDecisionProofValue["disposition"],
  sourceId: AlertEvaluatorSourceId,
): AlertEvaluatorDecisionProofValue {
  return {
    decisionSha256: `I${"A".repeat(42)}`,
    disposition,
    evaluationSha256: `E${"A".repeat(42)}`,
    identitySha256: DIGEST,
    ordinal: 0,
    sourceId,
  };
}

function wrapRunThenThrow(statement: D1PreparedStatement): D1PreparedStatement {
  return new Proxy(statement, {
    get(target, property) {
      if (property === "bind") {
        return (...values: unknown[]) => wrapRunThenThrow(target.bind(...values));
      }
      if (property === "run") {
        return async () => {
          await target.run();
          throw new Error("simulated response loss");
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function runThenThrowDatabase(queryFragment: string): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => {
          const statement = target.prepare(query);
          return query.includes(queryFragment)
            ? wrapRunThenThrow(statement)
            : statement;
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function throwBeforeRunDatabase(queryFragment: string): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => {
          const statement = target.prepare(query);
          if (!query.includes(queryFragment)) return statement;
          return new Proxy(statement, {
            get(prepared, preparedProperty) {
              if (preparedProperty === "bind") {
                return (...values: unknown[]) => {
                  const bound = prepared.bind(...values);
                  return new Proxy(bound, {
                    get(boundTarget, boundProperty) {
                      if (boundProperty === "run") {
                        return async () => {
                          throw new Error("simulated pre-execution failure");
                        };
                      }
                      const value: unknown = Reflect.get(
                        boundTarget,
                        boundProperty,
                        boundTarget,
                      );
                      return typeof value === "function"
                        ? value.bind(boundTarget)
                        : value;
                    },
                  });
                };
              }
              const value: unknown = Reflect.get(
                prepared,
                preparedProperty,
                prepared,
              );
              return typeof value === "function" ? value.bind(prepared) : value;
            },
          });
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function batchThenThrowDatabase(): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          await target.batch(statements);
          throw new Error("simulated response loss");
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

async function resetProofSchema(): Promise<void> {
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
  expect(bootstrapTriggers).toHaveLength(3);
  await env.PG72_ID_DB.batch([
    ...bootstrapTriggers.map((query) => env.PG72_ID_DB.prepare(query)),
    ...proofMigration.queries.map((query) => env.PG72_ID_DB.prepare(query)),
  ]);
}

async function acquire(
  database: D1Database = env.PG72_ID_DB,
  scheduledAt = at(60),
  startedAt = at(60),
): Promise<AlertEvaluatorRunFence> {
  const result = await acquireAlertEvaluatorRun(database, {
    leaseDurationSeconds: 180,
    scheduledAt,
    startedAt,
    triggerCron: "* * * * *",
  });
  if (!result || result.kind !== "acquired") throw new Error("expected run");
  return result.fence;
}

async function bindAndRecordSources(
  fence: AlertEvaluatorRunFence,
  partialSource: AlertEvaluatorSourceId | null = null,
): Promise<void> {
  expect(await bindAlertEvaluatorRunAsOf(env.PG72_ID_DB, fence, {
    asOf: at(70),
    boundAt: at(70),
  })).toMatchObject({ kind: "committed" });
  for (const sourceId of ALERT_EVALUATOR_SOURCE_IDS) {
    expect(await recordAlertEvaluatorRunSource(env.PG72_ID_DB, fence, {
      asOf: at(70),
      proof: proof(sourceId, sourceId === partialSource ? "partial" : "complete"),
      recordedAt: at(71),
    })).toBe("recorded");
  }
}

describe("alert evaluator run repository", () => {
  beforeEach(resetProofSchema);

  it("acquires, classifies a duplicate, and recovers a lost response", async () => {
    await initializeAlertEvaluatorRuntime(env.PG72_ID_DB, { initializedAt: at(0) });
    const fence = await acquire(runThenThrowDatabase("INSERT INTO alert_evaluator_run"));
    expect(await readAlertEvaluatorRun(env.PG72_ID_DB, fence.runId)).toMatchObject({
      status: "running",
      triggerScheduledAt: at(60),
    });
    expect(await acquireAlertEvaluatorRun(env.PG72_ID_DB, {
      leaseDurationSeconds: 180,
      scheduledAt: at(60),
      startedAt: at(61),
      triggerCron: "* * * * *",
    })).toMatchObject({ kind: "duplicate" });
    expect(await acquireAlertEvaluatorRun(env.PG72_ID_DB, {
      leaseDurationSeconds: 180,
      scheduledAt: at(120),
      startedAt: at(120),
      triggerCron: "* * * * *",
    })).toBeNull();
  });

  it("does not classify a pre-execution acquire failure as contention", async () => {
    await initializeAlertEvaluatorRuntime(env.PG72_ID_DB, { initializedAt: at(0) });
    await expect(acquireAlertEvaluatorRun(
      throwBeforeRunDatabase("INSERT INTO alert_evaluator_run"),
      {
        leaseDurationSeconds: 180,
        scheduledAt: at(60),
        startedAt: at(60),
        triggerCron: "* * * * *",
      },
    )).rejects.toEqual(new AlertRunRepositoryError("write_failed"));
    expect(await env.PG72_ID_DB.prepare(
      "SELECT count(*) AS count FROM alert_evaluator_run",
    ).first("count")).toBe(0);
  });

  it("renews running and sealed runs with exact response-loss replay", async () => {
    await initializeAlertEvaluatorRuntime(env.PG72_ID_DB, { initializedAt: at(0) });
    const first = await acquire();
    const renewed = await renewAlertEvaluatorRun(
      runThenThrowDatabase("UPDATE alert_evaluator_run\n          SET lease_revision"),
      first,
      { leaseDurationSeconds: 180, renewedAt: at(61) },
    );
    expect(renewed).toMatchObject({ kind: "replayed" });
    if (renewed.kind === "lost") throw new Error("expected renewed run");
    const replay = await renewAlertEvaluatorRun(env.PG72_ID_DB, first, {
      leaseDurationSeconds: 180,
      renewedAt: at(61),
    });
    expect(replay).toMatchObject({ kind: "replayed" });

    await bindAndRecordSources(renewed.fence);
    const sealed = await sealAlertEvaluatorRunPlan(
      env.PG72_ID_DB,
      renewed.fence,
      { decisions: [], sealedAt: at(72) },
    );
    expect(sealed).toMatchObject({ kind: "committed" });
    if (sealed.kind === "lost") throw new Error("expected sealed run");
    expect(await renewAlertEvaluatorRun(env.PG72_ID_DB, sealed.fence, {
      leaseDurationSeconds: 180,
      renewedAt: at(73),
    })).toMatchObject({ kind: "committed", run: { status: "sealed" } });
  });

  it("recovers bind, source, and seal response loss without accepting conflict", async () => {
    await initializeAlertEvaluatorRuntime(env.PG72_ID_DB, { initializedAt: at(0) });
    const fence = await acquire();
    expect(await bindAlertEvaluatorRunAsOf(
      runThenThrowDatabase("UPDATE alert_evaluator_run SET as_of"),
      fence,
      { asOf: at(70), boundAt: at(70) },
    )).toMatchObject({ kind: "replayed" });
    const firstSource = ALERT_EVALUATOR_SOURCE_IDS[0];
    expect(await recordAlertEvaluatorRunSource(
      runThenThrowDatabase("INSERT INTO alert_evaluator_run_source"),
      fence,
      { asOf: at(70), proof: proof(firstSource), recordedAt: at(71) },
    )).toBe("replayed");
    await expect(recordAlertEvaluatorRunSource(env.PG72_ID_DB, fence, {
      asOf: at(70),
      proof: { ...proof(firstSource), observationCount: 2 },
      recordedAt: at(71),
    })).rejects.toEqual(new AlertRunRepositoryError("conflict"));
    for (const sourceId of ALERT_EVALUATOR_SOURCE_IDS.slice(1)) {
      await recordAlertEvaluatorRunSource(env.PG72_ID_DB, fence, {
        asOf: at(70),
        proof: proof(sourceId),
        recordedAt: at(71),
      });
    }
    expect(await sealAlertEvaluatorRunPlan(
      runThenThrowDatabase("SET status = 'sealed'"),
      fence,
      { decisions: [], sealedAt: at(72) },
    )).toMatchObject({ kind: "replayed", run: { status: "sealed" } });
  });

  it("records only source-attributed suppression and fails with an exact pair", async () => {
    await initializeAlertEvaluatorRuntime(env.PG72_ID_DB, { initializedAt: at(0) });
    const fence = await acquire();
    const partial = ALERT_EVALUATOR_SOURCE_IDS[0];
    await bindAndRecordSources(fence, partial);
    const planned = {
      ...decision("suppressed_partial", partial),
      disposition: "suppressed_partial" as const,
    };
    await sealAlertEvaluatorRunPlan(env.PG72_ID_DB, fence, {
      decisions: [planned],
      sealedAt: at(72),
    });
    expect(await recordSuppressedAlertEvaluatorDecision(
      runThenThrowDatabase("INSERT INTO alert_evaluator_run_decision"),
      fence,
      { asOf: at(70), proof: planned, recordedAt: at(73) },
    )).toBe("replayed");
    const failed = await recordAlertEvaluatorRunFailure(
      runThenThrowDatabase("UPDATE alert_runtime_status"),
      fence,
      {
        completedAt: at(74),
        errorCode: "source_incomplete",
        status: "degraded",
      },
    );
    expect(failed).toMatchObject({ kind: "replayed", run: { status: "failed" } });
    expect(await recordAlertEvaluatorRunFailure(env.PG72_ID_DB, fence, {
      completedAt: at(74),
      errorCode: "metrics_unavailable",
      status: "unavailable",
    })).toEqual({ kind: "lost" });
    expect(await recordAlertEvaluatorRunFailure(env.PG72_ID_DB, {
      ...fence,
      startedAt: at(59),
    }, {
      completedAt: at(74),
      errorCode: "source_incomplete",
      status: "degraded",
    })).toEqual({ kind: "lost" });
  });

  it("commits success/bootstrap and recovers a lost terminal batch response", async () => {
    await initializeAlertEvaluatorRuntime(env.PG72_ID_DB, { initializedAt: at(0) });
    const fence = await acquire();
    await bindAndRecordSources(fence);
    const noState = {
      ...decision("no_state_change", "d1.audit"),
      disposition: "no_state_change" as const,
    };
    await sealAlertEvaluatorRunPlan(env.PG72_ID_DB, fence, {
      decisions: [noState],
      sealedAt: at(72),
    });
    expect(await recordNoStateChangeAlertEvaluatorDecision(
      runThenThrowDatabase("INSERT INTO alert_evaluator_run_decision"),
      fence,
      {
        absence: {
          environment: "local",
          queueName: null,
          ruleId: "pgid.registration.rate_limited.v1",
          sourceKind: "d1_exact",
          subjectRef: null,
        },
        asOf: at(70),
        proof: noState,
        recordedAt: at(73),
      },
    )).toBe("replayed");
    await expect(recordNoStateChangeAlertEvaluatorDecision(
      env.PG72_ID_DB,
      fence,
      {
        absence: {
          environment: "local",
          queueName: null,
          ruleId: "pgid.registration.rate_limited.v1",
          sourceKind: "d1_exact",
          subjectRef: null,
        },
        asOf: at(70),
        proof: { ...noState, decisionSha256: `Q${"A".repeat(42)}` },
        recordedAt: at(73),
      },
    )).rejects.toEqual(new AlertRunRepositoryError("conflict"));
    const success = await recordAlertEvaluatorRunSuccess(
      batchThenThrowDatabase(),
      fence,
      { completedAt: at(74) },
    );
    expect(success).toMatchObject({ kind: "replayed", run: { status: "succeeded" } });
    expect(await env.PG72_ID_DB.prepare(
      "SELECT count(*) AS count FROM alert_evaluator_bootstrap",
    ).first("count")).toBe(1);
    expect(await recordAlertEvaluatorRunSuccess(env.PG72_ID_DB, fence, {
      completedAt: at(74),
    })).toMatchObject({ kind: "replayed" });
  });

  it("atomically abandons an expired run during takeover", async () => {
    await initializeAlertEvaluatorRuntime(env.PG72_ID_DB, { initializedAt: at(0) });
    const first = await acquire(env.PG72_ID_DB, at(60), at(60));
    const second = await acquire(env.PG72_ID_DB, at(240), at(240));
    expect(second.runtimeGeneration).toBe(first.runtimeGeneration + 1);
    expect(await readAlertEvaluatorRun(env.PG72_ID_DB, first.runId)).toMatchObject({
      status: "abandoned",
      completedAt: at(240),
    });
  });

  it("preserves millisecond ownership through exact-expiry takeover", async () => {
    await initializeAlertEvaluatorRuntime(env.PG72_ID_DB, { initializedAt: at(0) });
    const firstResult = await acquireAlertEvaluatorRun(env.PG72_ID_DB, {
      leaseDurationSeconds: 1,
      scheduledAt: atMilliseconds(20_500),
      startedAt: atMilliseconds(20_500),
      triggerCron: "* * * * *",
    });
    if (!firstResult || firstResult.kind !== "acquired") {
      throw new Error("expected first millisecond run");
    }
    expect(firstResult.fence.leaseExpiresAt).toBe(atMilliseconds(21_500));
    expect(await acquireAlertEvaluatorRun(env.PG72_ID_DB, {
      leaseDurationSeconds: 1,
      scheduledAt: atMilliseconds(21_100),
      startedAt: atMilliseconds(21_100),
      triggerCron: "* * * * *",
    })).toBeNull();

    const takeover = await acquireAlertEvaluatorRun(env.PG72_ID_DB, {
      leaseDurationSeconds: 2,
      scheduledAt: atMilliseconds(21_500),
      startedAt: atMilliseconds(21_500),
      triggerCron: "* * * * *",
    });
    if (!takeover || takeover.kind !== "acquired") {
      throw new Error("expected exact-expiry takeover");
    }
    expect(takeover.fence.runtimeGeneration).toBe(
      firstResult.fence.runtimeGeneration + 1,
    );
    expect(await renewAlertEvaluatorRun(env.PG72_ID_DB, firstResult.fence, {
      leaseDurationSeconds: 1,
      renewedAt: atMilliseconds(21_200),
    })).toEqual({ kind: "lost" });
    expect(await recordAlertEvaluatorRunFailure(
      env.PG72_ID_DB,
      firstResult.fence,
      {
        completedAt: atMilliseconds(21_400),
        errorCode: "evaluator_failed",
        status: "failing",
      },
    )).toEqual({ kind: "lost" });
    expect(await recordAlertEvaluatorRunFailure(
      env.PG72_ID_DB,
      takeover.fence,
      {
        completedAt: atMilliseconds(22_000),
        errorCode: "evaluator_failed",
        status: "failing",
      },
    )).toMatchObject({ kind: "committed", run: { status: "failed" } });
  });
});
