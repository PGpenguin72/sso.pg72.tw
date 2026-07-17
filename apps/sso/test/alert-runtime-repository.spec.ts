import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import {
  acquireAlertEvaluatorLease,
  AlertRuntimeRepositoryError,
  initializeAlertEvaluatorRuntime,
  readAlertRuntimeThresholdInput,
  recordAlertEvaluatorFailure,
  recordAlertEvaluatorSuccess,
  renewAlertEvaluatorLease,
} from "../worker/alert-runtime-repository";
import { ALERT_RUNTIME_SOURCE_QUERY } from "../worker/alert-rules";

const BASE_TIME = new Date("2026-07-18T00:00:00.000Z").getTime();

function at(seconds: number): string {
  return new Date(BASE_TIME + seconds * 1_000).toISOString();
}

function atMilliseconds(milliseconds: number): string {
  return new Date(BASE_TIME + milliseconds).toISOString();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function proxyDatabase(
  overrides: {
    batch?: (
      target: D1Database,
      statements: D1PreparedStatement[],
    ) => Promise<D1Result[]>;
    prepare?: (
      target: D1Database,
      query: string,
    ) => D1PreparedStatement;
  },
): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch" && overrides.batch) {
        return (statements: D1PreparedStatement[]) =>
          overrides.batch?.(target, statements);
      }
      if (property === "prepare" && overrides.prepare) {
        return (query: string) => overrides.prepare?.(target, query);
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function transformProjectionDatabase(
  transform: (projection: unknown) => unknown,
): D1Database {
  return proxyDatabase({
    prepare(target, query) {
      const statement = target.prepare(query);
      if (query !== ALERT_RUNTIME_SOURCE_QUERY) return statement;
      return new Proxy(statement, {
        get(prepared, property) {
          if (property === "first") {
            return async () => transform(await prepared.first());
          }
          const value: unknown = Reflect.get(prepared, property, prepared);
          return typeof value === "function" ? value.bind(prepared) : value;
        },
      });
    },
  });
}

function replaceRuntimeTableDatabase(tableName: string): D1Database {
  return proxyDatabase({
    prepare(target, query) {
      return target.prepare(query.replaceAll("alert_runtime_status", tableName));
    },
  });
}

interface RuntimeRow {
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

interface BootstrapRow {
  component: string;
  first_success_at: string;
  source_generation: number;
  source_revision: number;
}

async function runtimeRow(): Promise<RuntimeRow | null> {
  return env.PG72_ID_DB.prepare(
    `SELECT status, generation, revision, lease_id, lease_expires_at,
            last_started_at, last_success_at, last_error_at,
            last_error_code, watermark_at, updated_at
       FROM alert_runtime_status
      WHERE component = 'evaluator'`,
  ).first<RuntimeRow>();
}

async function bootstrapRow(): Promise<BootstrapRow | null> {
  return env.PG72_ID_DB.prepare(
    `SELECT component, first_success_at, source_generation, source_revision
       FROM alert_evaluator_bootstrap
      WHERE component = 'evaluator'`,
  ).first<BootstrapRow>();
}

describe.sequential("alert evaluator runtime repository", () => {
  it("keeps initialization pre-bootstrap and rejects caller proof", async () => {
    await expect(
      initializeAlertEvaluatorRuntime(env.PG72_ID_DB, {
        initializedAt: "+010000-01-01T00:00:00.000Z",
      }),
    ).rejects.toEqual(new AlertRuntimeRepositoryError("invalid_input"));
    expect(await readAlertRuntimeThresholdInput(env.PG72_ID_DB, at(0)))
      .toBeNull();
    expect(
      await initializeAlertEvaluatorRuntime(env.PG72_ID_DB, {
        initializedAt: at(0),
      }),
    ).toBe(true);
    expect(
      await initializeAlertEvaluatorRuntime(env.PG72_ID_DB, {
        initializedAt: at(0),
      }),
    ).toBe(false);
    expect(await readAlertRuntimeThresholdInput(env.PG72_ID_DB, at(0)))
      .toBeNull();

    await expect(
      Reflect.apply(acquireAlertEvaluatorLease, undefined, [
        env.PG72_ID_DB,
        { leaseDurationSeconds: 120, startedAt: at(1) },
        { controlled: true },
      ]),
    ).rejects.toMatchObject({ code: "invalid_input" });

    const firstLease = await acquireAlertEvaluatorLease(env.PG72_ID_DB, {
      leaseDurationSeconds: 120,
      startedAt: at(1),
    });
    expect(firstLease).toMatchObject({
      component: "evaluator",
      generation: 1,
      revision: 1,
      startedAt: at(1),
      updatedAt: at(1),
    });
    if (!firstLease) throw new Error("expected the first evaluator lease");

    expect(
      await acquireAlertEvaluatorLease(env.PG72_ID_DB, {
        leaseDurationSeconds: 120,
        startedAt: at(2),
      }),
    ).toBeNull();
    await expect(
      Reflect.apply(recordAlertEvaluatorSuccess, undefined, [
        env.PG72_ID_DB,
        firstLease,
        { completedAt: at(3), watermarkAt: at(1) },
        { successfulRun: true },
      ]),
    ).rejects.toMatchObject({ code: "invalid_input" });

    const renewed = await renewAlertEvaluatorLease(
      env.PG72_ID_DB,
      firstLease,
      { leaseDurationSeconds: 120, renewedAt: at(2) },
    );
    expect(renewed).toMatchObject({
      generation: 1,
      revision: 2,
      startedAt: at(1),
      updatedAt: at(2),
    });
    if (!renewed) throw new Error("expected a renewed evaluator lease");

    expect(
      await recordAlertEvaluatorFailure(env.PG72_ID_DB, firstLease, {
        completedAt: at(3),
        errorCode: "evaluator_failed",
        status: "degraded",
      }),
    ).toBe(false);
    expect(
      await recordAlertEvaluatorFailure(env.PG72_ID_DB, renewed, {
        completedAt: at(3),
        errorCode: "evaluator_failed",
        status: "degraded",
      }),
    ).toBe(true);
    expect(await runtimeRow()).toEqual({
      generation: 1,
      last_error_at: at(3),
      last_error_code: "evaluator_failed",
      last_started_at: at(1),
      last_success_at: null,
      lease_expires_at: null,
      lease_id: null,
      revision: 3,
      status: "degraded",
      updated_at: at(3),
      watermark_at: null,
    });
    expect(await bootstrapRow()).toBeNull();
  });

  it("records failing and unavailable outcomes without forging bootstrap", async () => {
    const failingLease = await acquireAlertEvaluatorLease(env.PG72_ID_DB, {
      leaseDurationSeconds: 120,
      startedAt: at(4),
    });
    if (!failingLease) throw new Error("expected a failing-run lease");
    expect(
      await recordAlertEvaluatorFailure(env.PG72_ID_DB, failingLease, {
        completedAt: at(5),
        errorCode: "source_incomplete",
        status: "failing",
      }),
    ).toBe(true);
    expect(await runtimeRow()).toMatchObject({
      generation: 2,
      last_error_at: at(5),
      last_error_code: "source_incomplete",
      revision: 5,
      status: "failing",
    });

    const unavailableLease = await acquireAlertEvaluatorLease(env.PG72_ID_DB, {
      leaseDurationSeconds: 120,
      startedAt: at(6),
    });
    if (!unavailableLease) throw new Error("expected an unavailable-run lease");
    expect(
      await recordAlertEvaluatorFailure(env.PG72_ID_DB, unavailableLease, {
        completedAt: at(7),
        errorCode: "metrics_unavailable",
        status: "unavailable",
      }),
    ).toBe(true);
    expect(await runtimeRow()).toMatchObject({
      generation: 3,
      last_error_at: at(7),
      last_error_code: "metrics_unavailable",
      revision: 7,
      status: "unavailable",
    });
    expect(await bootstrapRow()).toBeNull();
    expect(await readAlertRuntimeThresholdInput(env.PG72_ID_DB, at(8)))
      .toBeNull();
  });

  it("rolls back the first-success batch before creating one bootstrap", async () => {
    const lease = await acquireAlertEvaluatorLease(env.PG72_ID_DB, {
      leaseDurationSeconds: 120,
      startedAt: at(8),
    });
    if (!lease) throw new Error("expected a first-success lease");

    let observedStatementCount = 0;
    const failingDatabase = proxyDatabase({
      batch: async (target, statements) => {
        observedStatementCount = statements.length;
        return target.batch([
          ...statements,
          target.prepare(
            `INSERT INTO alert_runtime_status (component, updated_at)
             VALUES ('evaluator', ?)`,
          ).bind(at(9)),
        ]);
      },
    });
    const failedWrite = await recordAlertEvaluatorSuccess(
      failingDatabase,
      lease,
      {
        completedAt: at(9),
        watermarkAt: at(8),
      },
    ).catch((error: unknown) => error);
    expect(failedWrite).toEqual(
      new AlertRuntimeRepositoryError("write_failed"),
    );
    expect(String(failedWrite)).not.toContain("UNIQUE constraint failed");
    expect(observedStatementCount).toBe(2);
    expect(await runtimeRow()).toMatchObject({
      generation: 4,
      last_success_at: null,
      lease_expires_at: lease.leaseExpiresAt,
      lease_id: lease.leaseId,
      revision: 8,
      status: "unavailable",
      updated_at: at(8),
      watermark_at: null,
    });
    expect(await bootstrapRow()).toBeNull();

    expect(
      await recordAlertEvaluatorSuccess(env.PG72_ID_DB, lease, {
        completedAt: at(9),
        watermarkAt: at(8),
      }),
    ).toEqual({ bootstrapCreated: true, committed: true });
    expect(await runtimeRow()).toMatchObject({
      generation: 4,
      last_success_at: at(9),
      lease_expires_at: null,
      lease_id: null,
      revision: 9,
      status: "healthy",
      updated_at: at(9),
      watermark_at: at(8),
    });
    expect(await bootstrapRow()).toEqual({
      component: "evaluator",
      first_success_at: at(9),
      source_generation: 4,
      source_revision: 9,
    });
    expect(await readAlertRuntimeThresholdInput(env.PG72_ID_DB, at(10)))
      .toEqual({ evaluatorAgeSeconds: 1 });
  });

  it("preserves bootstrap across later success and failure revisions", async () => {
    const repeatedLease = await acquireAlertEvaluatorLease(env.PG72_ID_DB, {
      leaseDurationSeconds: 120,
      startedAt: at(11),
    });
    if (!repeatedLease) throw new Error("expected a repeated-success lease");
    expect(
      await recordAlertEvaluatorSuccess(env.PG72_ID_DB, repeatedLease, {
        completedAt: at(12),
        watermarkAt: at(11),
      }),
    ).toEqual({ bootstrapCreated: false, committed: true });
    expect(await bootstrapRow()).toEqual({
      component: "evaluator",
      first_success_at: at(9),
      source_generation: 4,
      source_revision: 9,
    });

    const degradedLease = await acquireAlertEvaluatorLease(env.PG72_ID_DB, {
      leaseDurationSeconds: 120,
      startedAt: at(13),
    });
    if (!degradedLease) throw new Error("expected a post-bootstrap failure lease");
    expect(
      await recordAlertEvaluatorFailure(env.PG72_ID_DB, degradedLease, {
        completedAt: at(14),
        errorCode: "evaluator_failed",
        status: "degraded",
      }),
    ).toBe(true);
    expect(await runtimeRow()).toMatchObject({
      generation: 6,
      last_error_at: at(14),
      last_error_code: "evaluator_failed",
      last_success_at: at(12),
      revision: 13,
      status: "degraded",
      watermark_at: at(11),
    });
    expect(await readAlertRuntimeThresholdInput(env.PG72_ID_DB, at(15)))
      .toEqual({ evaluatorAgeSeconds: 3 });
  });

  it("owns the exact projection and fails closed with redacted errors", async () => {
    const queries: string[] = [];
    const recordingDatabase = proxyDatabase({
      prepare(target, query) {
        queries.push(query);
        return target.prepare(query);
      },
    });
    expect(await readAlertRuntimeThresholdInput(recordingDatabase, at(15)))
      .toEqual({ evaluatorAgeSeconds: 3 });
    expect(queries).toEqual([ALERT_RUNTIME_SOURCE_QUERY]);

    const missingDatabase = transformProjectionDatabase(() => null);
    await expect(
      readAlertRuntimeThresholdInput(missingDatabase, at(15)),
    ).rejects.toEqual(new AlertRuntimeRepositoryError("source_invalid"));

    const corruptDatabase = transformProjectionDatabase((projection) =>
      isRecord(projection) ? { ...projection, caller_proof: true } : projection,
    );
    await expect(
      readAlertRuntimeThresholdInput(corruptDatabase, at(15)),
    ).rejects.toEqual(new AlertRuntimeRepositoryError("source_invalid"));

    const missingRuntimeDatabase = transformProjectionDatabase((projection) => {
      if (!isRecord(projection)) return projection;
      return {
        ...projection,
        runtime_component: null,
        runtime_generation: null,
        runtime_last_error_at: null,
        runtime_last_error_code: null,
        runtime_last_started_at: null,
        runtime_last_success_at: null,
        runtime_revision: null,
        runtime_status: null,
        runtime_updated_at: null,
      };
    });
    expect(
      await readAlertRuntimeThresholdInput(missingRuntimeDatabase, at(15)),
    ).toEqual({ evaluatorAgeSeconds: null });

    const unavailableDatabase = proxyDatabase({
      prepare(_target, query) {
        if (query === ALERT_RUNTIME_SOURCE_QUERY) {
          throw new Error("database failed with sensitive-row-value");
        }
        return env.PG72_ID_DB.prepare(query);
      },
    });
    const unavailable = await readAlertRuntimeThresholdInput(
      unavailableDatabase,
      at(15),
    ).catch((error: unknown) => error);
    expect(unavailable).toEqual(
      new AlertRuntimeRepositoryError("source_unavailable"),
    );
    expect(String(unavailable)).not.toContain("sensitive-row-value");

    await expect(
      env.PG72_ID_DB.prepare(
        "DELETE FROM alert_runtime_status WHERE component = 'evaluator'",
      ).run(),
    ).rejects.toThrow();
    expect(
      (await env.PG72_ID_DB.prepare("PRAGMA foreign_key_check").all()).results,
    ).toEqual([]);
  });

  it("preserves millisecond lease ownership through exact expiry", async () => {
    const sameSecondLease = await acquireAlertEvaluatorLease(env.PG72_ID_DB, {
      leaseDurationSeconds: 1,
      startedAt: atMilliseconds(20_500),
    });
    if (!sameSecondLease) throw new Error("expected a same-second lease");
    expect(sameSecondLease.leaseExpiresAt).toBe(atMilliseconds(21_500));

    expect(
      await acquireAlertEvaluatorLease(env.PG72_ID_DB, {
        leaseDurationSeconds: 1,
        startedAt: atMilliseconds(21_100),
      }),
    ).toBeNull();
    expect(await runtimeRow()).toMatchObject({
      generation: sameSecondLease.generation,
      lease_expires_at: atMilliseconds(21_500),
      lease_id: sameSecondLease.leaseId,
      revision: sameSecondLease.revision,
      updated_at: atMilliseconds(20_500),
    });

    const exactExpiryLease = await acquireAlertEvaluatorLease(
      env.PG72_ID_DB,
      {
        leaseDurationSeconds: 2,
        startedAt: atMilliseconds(21_500),
      },
    );
    if (!exactExpiryLease) throw new Error("expected exact-expiry takeover");
    expect(exactExpiryLease.generation).toBe(sameSecondLease.generation + 1);
    expect(
      await recordAlertEvaluatorFailure(env.PG72_ID_DB, exactExpiryLease, {
        completedAt: atMilliseconds(22_000),
        errorCode: "evaluator_failed",
        status: "degraded",
      }),
    ).toBe(true);

    const crossSecondLease = await acquireAlertEvaluatorLease(env.PG72_ID_DB, {
      leaseDurationSeconds: 1,
      startedAt: atMilliseconds(23_100),
    });
    if (!crossSecondLease) throw new Error("expected a cross-second lease");
    expect(crossSecondLease.leaseExpiresAt).toBe(atMilliseconds(24_100));
    expect(
      await acquireAlertEvaluatorLease(env.PG72_ID_DB, {
        leaseDurationSeconds: 1,
        startedAt: atMilliseconds(23_900),
      }),
    ).toBeNull();

    const crossSecondTakeover = await acquireAlertEvaluatorLease(
      env.PG72_ID_DB,
      {
        leaseDurationSeconds: 2,
        startedAt: atMilliseconds(24_100),
      },
    );
    if (!crossSecondTakeover) {
      throw new Error("expected cross-second exact-expiry takeover");
    }
    expect(
      await recordAlertEvaluatorFailure(env.PG72_ID_DB, crossSecondTakeover, {
        completedAt: atMilliseconds(25_000),
        errorCode: "evaluator_failed",
        status: "degraded",
      }),
    ).toBe(true);
  });

  it("reserves the final revision for terminal lease release", async () => {
    const tableName = "alert_runtime_status_revision_boundary";
    const boundaryDatabase = replaceRuntimeTableDatabase(tableName);
    await env.PG72_ID_DB.prepare(
      `CREATE TABLE ${tableName} (
        component TEXT PRIMARY KEY NOT NULL,
        status TEXT NOT NULL,
        generation INTEGER NOT NULL,
        revision INTEGER NOT NULL,
        lease_id TEXT,
        lease_expires_at TEXT,
        last_started_at TEXT,
        last_success_at TEXT,
        last_error_at TEXT,
        last_error_code TEXT,
        watermark_at TEXT,
        updated_at TEXT NOT NULL
      )`,
    ).run();

    try {
      await env.PG72_ID_DB.prepare(
        `INSERT INTO ${tableName}
          (component, status, generation, revision, updated_at)
         VALUES ('evaluator', 'healthy', 1, 999999999, ?)`,
      )
        .bind(at(30))
        .run();
      expect(
        await acquireAlertEvaluatorLease(boundaryDatabase, {
          leaseDurationSeconds: 120,
          startedAt: at(31),
        }),
      ).toBeNull();

      const maxMinusOneLease = {
        component: "evaluator" as const,
        generation: 1,
        leaseExpiresAt: at(60),
        leaseId: crypto.randomUUID(),
        revision: 999_999_999,
        startedAt: at(31),
        updatedAt: at(31),
      };
      await env.PG72_ID_DB.prepare(
        `UPDATE ${tableName}
            SET lease_id = ?, lease_expires_at = ?, last_started_at = ?,
                updated_at = ?
          WHERE component = 'evaluator'`,
      )
        .bind(
          maxMinusOneLease.leaseId,
          maxMinusOneLease.leaseExpiresAt,
          maxMinusOneLease.startedAt,
          maxMinusOneLease.updatedAt,
        )
        .run();
      await expect(
        renewAlertEvaluatorLease(boundaryDatabase, maxMinusOneLease, {
          leaseDurationSeconds: 120,
          renewedAt: at(32),
        }),
      ).rejects.toEqual(new AlertRuntimeRepositoryError("invalid_input"));

      await env.PG72_ID_DB.prepare(
        `UPDATE ${tableName}
            SET revision = 999999998, lease_id = NULL,
                lease_expires_at = NULL, last_started_at = NULL,
                updated_at = ?
          WHERE component = 'evaluator'`,
      )
        .bind(at(30))
        .run();
      const lastLegalLease = await acquireAlertEvaluatorLease(
        boundaryDatabase,
        { leaseDurationSeconds: 120, startedAt: at(31) },
      );
      expect(lastLegalLease).toMatchObject({
        generation: 2,
        revision: 999_999_999,
      });
      if (!lastLegalLease) throw new Error("expected the last legal lease");
      expect(
        await recordAlertEvaluatorFailure(boundaryDatabase, lastLegalLease, {
          completedAt: at(32),
          errorCode: "evaluator_failed",
          status: "degraded",
        }),
      ).toBe(true);
      expect(
        await env.PG72_ID_DB.prepare(
          `SELECT revision, lease_id, lease_expires_at
             FROM ${tableName}
            WHERE component = 'evaluator'`,
        ).first(),
      ).toEqual({
        lease_expires_at: null,
        lease_id: null,
        revision: 1_000_000_000,
      });
      expect(
        await acquireAlertEvaluatorLease(boundaryDatabase, {
          leaseDurationSeconds: 120,
          startedAt: at(33),
        }),
      ).toBeNull();
    } finally {
      await env.PG72_ID_DB.prepare(`DROP TABLE ${tableName}`).run();
    }
  });
});
