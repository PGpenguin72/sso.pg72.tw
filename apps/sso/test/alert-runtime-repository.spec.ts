import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";

import {
  acquireAlertEvaluatorLease,
  AlertRuntimeRepositoryError,
  initializeAlertEvaluatorRuntime,
  readAlertRuntimeThresholdInput,
  recordAlertEvaluatorFailure,
  recordAlertEvaluatorSuccess,
  renewAlertEvaluatorLease,
} from "../worker/alert-runtime-repository";
import { acquireAlertEvaluatorRun } from "../worker/alert-run-repository";
import {
  ALERT_RUNTIME_GENERATION_MAX,
  ALERT_RUNTIME_REVISION_MAX,
  ALERT_RUNTIME_SOURCE_QUERY,
} from "../worker/alert-rules";

const BASE_TIME = new Date("2026-07-18T00:00:00.000Z").getTime();

function at(seconds: number): string {
  return new Date(BASE_TIME + seconds * 1_000).toISOString();
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

function replaceRuntimeTableDatabase(
  tableName: string,
  bootstrapTableName = "alert_evaluator_bootstrap",
): D1Database {
  return proxyDatabase({
    prepare(target, query) {
      return target.prepare(
        query
          .replaceAll("alert_runtime_status", tableName)
          .replaceAll("alert_evaluator_bootstrap", bootstrapTableName),
      );
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
  it("keeps initialization pre-bootstrap and rejects legacy acquire", async () => {
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

    await expect(
      acquireAlertEvaluatorLease(env.PG72_ID_DB, {
        leaseDurationSeconds: 120,
        startedAt: at(1),
      }),
    ).rejects.toEqual(new AlertRuntimeRepositoryError("write_failed"));
    await expect(
      Reflect.apply(recordAlertEvaluatorSuccess, undefined, [
        env.PG72_ID_DB,
        {
          component: "evaluator",
          generation: 1,
          leaseExpiresAt: at(121),
          leaseId: crypto.randomUUID(),
          revision: 1,
          startedAt: at(1),
          updatedAt: at(1),
        },
        { completedAt: at(3), watermarkAt: at(1) },
        { successfulRun: true },
      ]),
    ).rejects.toMatchObject({ code: "invalid_input" });
    expect(await runtimeRow()).toEqual({
      generation: 0,
      last_error_at: null,
      last_error_code: null,
      last_started_at: null,
      last_success_at: null,
      lease_expires_at: null,
      lease_id: null,
      revision: 0,
      status: "disabled",
      updated_at: at(0),
      watermark_at: null,
    });
    expect(await bootstrapRow()).toBeNull();
  });

  it("rejects legacy renew and terminal writes against a run-owned lease", async () => {
    const acquired = await acquireAlertEvaluatorRun(env.PG72_ID_DB, {
      leaseDurationSeconds: 120,
      scheduledAt: at(1),
      startedAt: at(1),
      triggerCron: "* * * * *",
    });
    if (!acquired || acquired.kind !== "acquired") {
      throw new Error("expected a run-owned lease");
    }
    const lease = {
      component: "evaluator" as const,
      generation: acquired.fence.runtimeGeneration,
      leaseExpiresAt: acquired.fence.leaseExpiresAt,
      leaseId: acquired.fence.leaseId,
      revision: acquired.fence.leaseRevision,
      startedAt: acquired.fence.startedAt,
      updatedAt: acquired.fence.leaseUpdatedAt,
    };
    await expect(renewAlertEvaluatorLease(env.PG72_ID_DB, lease, {
      leaseDurationSeconds: 120,
      renewedAt: at(2),
    })).rejects.toEqual(new AlertRuntimeRepositoryError("write_failed"));
    await expect(recordAlertEvaluatorFailure(env.PG72_ID_DB, lease, {
      completedAt: at(3),
      errorCode: "evaluator_failed",
      status: "degraded",
    })).rejects.toEqual(new AlertRuntimeRepositoryError("write_failed"));
    await expect(recordAlertEvaluatorSuccess(env.PG72_ID_DB, lease, {
      completedAt: at(3),
      watermarkAt: at(1),
    })).rejects.toEqual(new AlertRuntimeRepositoryError("write_failed"));
    expect(await runtimeRow()).toMatchObject({
      generation: acquired.fence.runtimeGeneration,
      lease_expires_at: acquired.fence.leaseExpiresAt,
      lease_id: acquired.fence.leaseId,
      revision: acquired.fence.leaseRevision,
      status: "disabled",
    });
    expect(await bootstrapRow()).toBeNull();
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
      .toBeNull();
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
    ).toBeNull();

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

    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await env.PG72_ID_DB.prepare(
        `INSERT INTO ${tableName}
          (component, status, generation, revision, updated_at)
         VALUES ('evaluator', 'healthy', 1, ?, ?)`,
      )
        .bind(Number.MAX_SAFE_INTEGER - 1, at(30))
        .run();
      await expect(
        acquireAlertEvaluatorLease(boundaryDatabase, {
          leaseDurationSeconds: 120,
          startedAt: at(31),
        }),
      ).rejects.toEqual(
        new AlertRuntimeRepositoryError("counter_exhausted"),
      );

      const maxMinusOneLease = {
        component: "evaluator" as const,
        generation: 1,
        leaseExpiresAt: at(60),
        leaseId: crypto.randomUUID(),
        revision: Number.MAX_SAFE_INTEGER - 1,
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
      ).rejects.toEqual(
        new AlertRuntimeRepositoryError("counter_exhausted"),
      );

      await env.PG72_ID_DB.prepare(
        `UPDATE ${tableName}
            SET revision = ?, lease_id = NULL,
                lease_expires_at = NULL, last_started_at = NULL,
                updated_at = ?
          WHERE component = 'evaluator'`,
      )
        .bind(Number.MAX_SAFE_INTEGER - 2, at(30))
        .run();
      const lastLegalLease = await acquireAlertEvaluatorLease(
        boundaryDatabase,
        { leaseDurationSeconds: 120, startedAt: at(31) },
      );
      expect(lastLegalLease).toMatchObject({
        generation: 2,
        revision: Number.MAX_SAFE_INTEGER - 1,
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
        revision: Number.MAX_SAFE_INTEGER,
      });
      await expect(
        acquireAlertEvaluatorLease(boundaryDatabase, {
          leaseDurationSeconds: 120,
          startedAt: at(33),
        }),
      ).rejects.toEqual(
        new AlertRuntimeRepositoryError("counter_exhausted"),
      );
      expect(errorLog).toHaveBeenCalledWith(expect.stringContaining(
        '"code":"counter_exhausted"',
      ));
    } finally {
      errorLog.mockRestore();
      await env.PG72_ID_DB.prepare(`DROP TABLE ${tableName}`).run();
    }
  });

  it("commits the last safe generation and revision with an exact bootstrap", async () => {
    const runtimeTable = "alert_runtime_status_safe_boundary";
    const bootstrapTable = "alert_evaluator_bootstrap_safe_boundary";
    const boundaryDatabase = replaceRuntimeTableDatabase(
      runtimeTable,
      bootstrapTable,
    );
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
    await env.PG72_ID_DB.prepare(
      `CREATE TABLE ${runtimeTable} (
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
    await env.PG72_ID_DB.prepare(
      `CREATE TABLE ${bootstrapTable} (
        component TEXT PRIMARY KEY NOT NULL,
        first_success_at TEXT NOT NULL,
        source_generation INTEGER NOT NULL,
        source_revision INTEGER NOT NULL
      )`,
    ).run();

    try {
      await env.PG72_ID_DB.prepare(
        `INSERT INTO ${runtimeTable}
          (component, status, generation, revision, updated_at)
         VALUES ('evaluator', 'healthy', ?, ?, ?)`,
      )
        .bind(
          ALERT_RUNTIME_GENERATION_MAX - 1,
          ALERT_RUNTIME_REVISION_MAX - 2,
          at(40),
        )
        .run();
      const lastLease = await acquireAlertEvaluatorLease(boundaryDatabase, {
        leaseDurationSeconds: 120,
        startedAt: at(41),
      });
      expect(lastLease).toMatchObject({
        generation: Number.MAX_SAFE_INTEGER,
        revision: Number.MAX_SAFE_INTEGER - 1,
      });
      if (!lastLease) throw new Error("expected the last safe evaluator lease");

      expect(
        await recordAlertEvaluatorSuccess(boundaryDatabase, lastLease, {
          completedAt: at(42),
          watermarkAt: at(41),
        }),
      ).toEqual({ bootstrapCreated: true, committed: true });
      expect(
        await env.PG72_ID_DB.prepare(
          `SELECT component, first_success_at, source_generation, source_revision
             FROM ${bootstrapTable}`,
        ).first(),
      ).toEqual({
        component: "evaluator",
        first_success_at: at(42),
        source_generation: Number.MAX_SAFE_INTEGER,
        source_revision: Number.MAX_SAFE_INTEGER,
      });
      expect(
        await readAlertRuntimeThresholdInput(boundaryDatabase, at(43)),
      ).toEqual({ evaluatorAgeSeconds: 1 });

      await env.PG72_ID_DB.prepare(
        `UPDATE ${runtimeTable}
            SET revision = 1, lease_id = NULL, lease_expires_at = NULL,
                updated_at = ?
          WHERE component = 'evaluator'`,
      )
        .bind(at(43))
        .run();
      const exhausted = await acquireAlertEvaluatorLease(boundaryDatabase, {
        leaseDurationSeconds: 120,
        startedAt: at(44),
      }).catch((error: unknown) => error);
      expect(exhausted).toEqual(
        new AlertRuntimeRepositoryError("counter_exhausted"),
      );
      expect(String(exhausted)).toBe(
        "AlertRuntimeRepositoryError: Alert runtime repository failed (counter_exhausted)",
      );
    } finally {
      errorLog.mockRestore();
      await env.PG72_ID_DB.prepare(`DROP TABLE ${bootstrapTable}`).run();
      await env.PG72_ID_DB.prepare(`DROP TABLE ${runtimeTable}`).run();
    }
  });
});
