import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import {
  ALERT_FANOUT_GAP_QUERY,
  ALERT_FANOUT_TIMESTAMP_INTEGRITY_QUERY,
  AlertFanoutSourceRepositoryError,
  readFanoutGapAlertSource,
  type FanoutGapAlertSourceResult,
} from "../worker/alert-fanout-source-repository";
import { evaluateAlertRule } from "../worker/alert-rules";

async function insertAudit(occurredAt: string): Promise<string> {
  const id = crypto.randomUUID();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event (id, event_type, outcome, occurred_at)
     VALUES (?, 'fanout.source_test', 'success', ?)`,
  )
    .bind(id, occurredAt)
    .run();
  return id;
}

async function insertDelivery(
  eventId: string,
  deliveredAt = "2032-01-01T00:00:00.000Z",
): Promise<void> {
  await env.PG72_ID_DB.prepare(
    `INSERT INTO security_event_delivery (event_id, delivered_at)
     VALUES (?, ?)`,
  )
    .bind(eventId, deliveredAt)
    .run();
}

function at(base: string, offsetMilliseconds: number): string {
  return new Date(new Date(base).getTime() + offsetMilliseconds).toISOString();
}

async function read(
  asOf: string,
  database: D1Database = env.PG72_ID_DB,
): Promise<FanoutGapAlertSourceResult> {
  return readFanoutGapAlertSource(database, { asOf });
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

function withRows(rows: readonly Record<string, unknown>[]): D1Database {
  return transformBatchDatabase((results) =>
    replaceResultRows(results, 1, rows)
  );
}

function withIntegrityRows(
  rows: readonly Record<string, unknown>[],
): D1Database {
  return transformBatchDatabase((results) =>
    replaceResultRows(results, 0, rows)
  );
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

function resultRow(
  missingOlderThan15mCount: unknown,
  missingOlderThan5mCount: unknown,
  invalidSourceTimestampCount: unknown = 0,
): Record<string, unknown> {
  return {
    invalid_source_timestamp_count: invalidSourceTimestampCount,
    missing_older_than_15m_count: missingOlderThan15mCount,
    missing_older_than_5m_count: missingOlderThan5mCount,
  };
}

function failingBatchDatabase(): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return async () => {
          throw new Error("database failure leaked private-token-forbidden");
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

describe.sequential("fan-out gap alert source repository", () => {
  it("uses the exact half-open lookback and strict five/fifteen-minute grace boundaries", async () => {
    const asOf = "2032-02-01T12:00:00.000Z";
    for (const offset of [
      -3_600_000,
      -900_001,
      -900_000,
      -899_999,
      -300_001,
      -300_000,
      -299_999,
      -1,
      0,
      -3_600_001,
    ]) {
      await insertAudit(at(asOf, offset));
    }

    const result = await read(asOf);
    expect(result.incomplete).toEqual([]);
    expect(result.observations).toEqual([{
      asOf,
      dimension: { kind: "global" },
      ruleId: "pgid.security.fanout_gap.v1",
      snapshot: {
        missingOlderThan15mCount: 2,
        missingOlderThan5mCount: 5,
      },
    }]);
    expect(evaluateAlertRule(result.observations[0])).toMatchObject({
      evidence: "known",
      severity: "critical",
    });
  });

  it("treats only a matching delivery marker as delivered", async () => {
    const asOf = "2032-02-02T12:00:00.000Z";
    const olderThan15m = await insertAudit(at(asOf, -1_000_000));
    await insertAudit(at(asOf, -600_001));
    const olderThan5m = await insertAudit(at(asOf, -600_000));
    await insertDelivery(olderThan15m, at(asOf, -1));
    await insertDelivery(olderThan5m, at(asOf, 1));
    await insertDelivery(crypto.randomUUID(), at(asOf, -1));

    const result = await read(asOf);
    expect(result.incomplete).toEqual([]);
    expect(result.observations[0]?.snapshot).toEqual({
      missingOlderThan15mCount: 0,
      missingOlderThan5mCount: 1,
    });
  });

  it("emits one known global zero observation for a valid empty cohort", async () => {
    const asOf = "2032-02-03T12:00:00.000Z";
    const result = await read(asOf);
    expect(result).toEqual({
      incomplete: [],
      observations: [{
        asOf,
        dimension: { kind: "global" },
        ruleId: "pgid.security.fanout_gap.v1",
        snapshot: {
          missingOlderThan15mCount: 0,
          missingOlderThan5mCount: 0,
        },
      }],
    });
    expect(evaluateAlertRule(result.observations[0])).toMatchObject({
      evidence: "known",
      severity: "none",
    });
  });

  it("preserves selected-row timestamp validation behind the global preflight", async () => {
    const asOf = "2032-02-04T12:00:00.000Z";
    const rawTimestamp = "2032-02-04T11:30:00Z";
    const failure = read(asOf, withRows([resultRow(0, 0, 1)]));
    await expect(failure).rejects.toEqual(
      new AlertFanoutSourceRepositoryError("source_invalid"),
    );
    await expect(failure).rejects.not.toThrow(rawTimestamp);
  });

  it("fails closed on global timestamp corruption before the lexical cohort", async () => {
    const asOf = "2032-02-04T13:00:00.000Z";
    const rawMarker = "raw-offset-time-must-not-leak";
    const corruptProjections = [
      [{ invalid_timestamp_exists: 1 }],
      [],
      [{ invalid_timestamp_exists: false }],
      [{ invalid_timestamp_exists: "0" }],
      [
        { invalid_timestamp_exists: 0 },
        { invalid_timestamp_exists: 0 },
      ],
      [{ invalid_timestamp_exists: 0, unexpected: rawMarker }],
    ];
    for (const projection of corruptProjections) {
      const failure = read(asOf, withIntegrityRows(projection));
      await expect(failure).rejects.toEqual(
        new AlertFanoutSourceRepositoryError("source_invalid"),
      );
      await expect(failure).rejects.not.toThrow(rawMarker);
    }
  });

  it("validates canonical input and the exact call shape", async () => {
    const invalidInputs = [
      null,
      [],
      {},
      { asOf: 42 },
      { asOf: "not-a-time" },
      { asOf: "2032-02-05T12:00:00Z" },
      { asOf: "2032-02-05T12:00:00.000Z", extra: true },
    ];
    for (const input of invalidInputs) {
      await expect(readFanoutGapAlertSource(
        env.PG72_ID_DB,
        input as { asOf: string },
      )).rejects.toEqual(
        new AlertFanoutSourceRepositoryError("invalid_input"),
      );
    }

    const variadic = readFanoutGapAlertSource as unknown as (
      ...args: unknown[]
    ) => Promise<FanoutGapAlertSourceResult>;
    await expect(variadic(env.PG72_ID_DB)).rejects.toEqual(
      new AlertFanoutSourceRepositoryError("invalid_input"),
    );
    await expect(variadic(
      env.PG72_ID_DB,
      { asOf: "2032-02-05T12:00:00.000Z" },
      "extra",
    )).rejects.toEqual(
      new AlertFanoutSourceRepositoryError("invalid_input"),
    );
  });

  it("accepts the safe cap and turns larger valid counts into incomplete evidence", async () => {
    const asOf = "2032-02-06T12:00:00.000Z";
    const atCap = await read(
      asOf,
      withRows([resultRow(1_000_000_000, 1_000_000_000)]),
    );
    expect(atCap.incomplete).toEqual([]);
    expect(atCap.observations[0]?.snapshot).toEqual({
      missingOlderThan15mCount: 1_000_000_000,
      missingOlderThan5mCount: 1_000_000_000,
    });

    await expect(read(
      asOf,
      withRows([resultRow(1_000_000_001, 1_000_000_001)]),
    )).resolves.toEqual({
      incomplete: [{
        dimensionKind: "global",
        ruleId: "pgid.security.fanout_gap.v1",
      }],
      observations: [],
    });
  });

  it("rejects corrupt counter types, ranges, timestamp evidence, and cohort nesting", async () => {
    const asOf = "2032-02-07T12:00:00.000Z";
    const corruptRows = [
      resultRow("1", 1),
      resultRow(1, -1),
      resultRow(0.5, 1),
      resultRow(Number.NaN, 1),
      resultRow(0, Number.POSITIVE_INFINITY),
      resultRow(2, 1),
      resultRow(0, 0, 1),
      resultRow(0, 0, "0"),
    ];
    for (const row of corruptRows) {
      await expect(read(asOf, withRows([row]))).rejects.toEqual(
        new AlertFanoutSourceRepositoryError("source_invalid"),
      );
    }
  });

  it("requires one successful D1 result with one exact projection row", async () => {
    const asOf = "2032-02-08T12:00:00.000Z";
    const exact = resultRow(0, 0);
    const corruptDatabases = [
      transformBatchDatabase(() => []),
      withRows([]),
      withRows([exact, exact]),
      withRows([{ ...exact, unexpected: "raw-private-value" }]),
      withRows([{
        invalid_source_timestamp_count: 0,
        missing_older_than_5m_count: 0,
      }]),
      transformBatchDatabase((results) =>
        results.map((result, index) =>
          index === 1
            ? {
              ...result,
              success: false,
            } as unknown as D1Result<Record<string, unknown>>
            : result
        )
      ),
      transformBatchDatabase((results) =>
        results.map((result, index) =>
          index === 1
            ? { ...result, results: undefined as never }
            : result
        )
      ),
    ];
    for (const database of corruptDatabases) {
      const failure = read(asOf, database);
      await expect(failure).rejects.toEqual(
        new AlertFanoutSourceRepositoryError("source_invalid"),
      );
      await expect(failure).rejects.not.toThrow("raw-private-value");
    }
  });

  it("redacts D1 execution failures", async () => {
    const failure = read(
      "2032-02-09T12:00:00.000Z",
      failingBatchDatabase(),
    );
    await expect(failure).rejects.toEqual(
      new AlertFanoutSourceRepositoryError("source_unavailable"),
    );
    await expect(failure).rejects.not.toThrow("private-token-forbidden");
  });

  it("pins the bounded source and marker query plans without projecting raw evidence", async () => {
    const asOf = "2032-02-10T12:00:00.000Z";
    const integrityPlan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN ${ALERT_FANOUT_TIMESTAMP_INTEGRITY_QUERY}`,
    ).all<{ detail: string }>();
    const integrityDetails = integrityPlan.results
      .map(({ detail }) => detail)
      .join("\n");
    expect(ALERT_FANOUT_TIMESTAMP_INTEGRITY_QUERY).toContain("LIMIT 1");
    expect(integrityDetails).toContain(
      "USING COVERING INDEX audit_event_invalid_occurred_at_idx",
    );
    expect(integrityDetails).not.toMatch(/SCAN audit_event$/m);
    const plan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN ${ALERT_FANOUT_GAP_QUERY}`,
    )
      .bind(
        at(asOf, -3_600_000),
        asOf,
        at(asOf, -900_000),
        at(asOf, -300_000),
      )
      .all<{ detail: string }>();
    const details = plan.results.map(({ detail }) => detail).join("\n");
    expect(details).toContain("audit_event_time_bounded_idx");
    expect(details).toMatch(/SEARCH source\b/);
    expect(details).toMatch(
      /SEARCH marker USING COVERING INDEX .*security_event_delivery.*LEFT-JOIN/,
    );
    for (const forbidden of [
      "actor_user_id",
      "client_id",
      "ip_hash",
      "metadata_json",
      "session_id",
      "subject_id",
      "user_agent_hash",
    ]) {
      expect(ALERT_FANOUT_GAP_QUERY).not.toContain(forbidden);
    }
  });
});
