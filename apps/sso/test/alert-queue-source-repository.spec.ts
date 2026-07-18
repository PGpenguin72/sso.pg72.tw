import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  ALERT_QUEUE_METRIC_CHANGES_QUERY,
  ALERT_QUEUE_METRIC_PROJECTION_QUERY,
  ALERT_QUEUE_METRIC_SAMPLE_UPSERT,
  AlertQueueSourceRepositoryError,
  persistQueueMetricSample,
  readQueueMetricsAlertSource,
  type QueueMetricSample,
  type QueueMetricsProvider,
} from "../worker/alert-queue-source-repository";
import {
  ALERT_QUEUE_COMPONENTS,
  ALERT_QUEUE_NAMES,
  evaluateAlertRule,
  type AlertQueueName,
} from "../worker/alert-rules";

const BASE = "2035-01-01T12:00:00.000Z";
const QUEUE_COMPONENTS = Object.values(ALERT_QUEUE_COMPONENTS);

function at(base: string, offsetMilliseconds: number): string {
  return new Date(new Date(base).getTime() + offsetMilliseconds).toISOString();
}

function clock(timestamp: string): () => Date {
  return () => new Date(timestamp);
}

function provider(value: unknown): QueueMetricsProvider {
  return { metrics: vi.fn().mockResolvedValue(value) };
}

function positiveMetrics(
  sampledAt: string,
  options: { backlogBytes?: number; backlogCount?: number; ageMs?: number } = {},
): Record<string, unknown> {
  return {
    backlogBytes: options.backlogBytes ?? 128,
    backlogCount: options.backlogCount ?? 1,
    oldestMessageTimestamp: new Date(
      new Date(sampledAt).getTime() - (options.ageMs ?? 1_250),
    ),
  };
}

function sample(
  sampledAt: string,
  options: {
    backlogBytes?: number;
    backlogCount?: number;
    oldestMessageAgeSeconds?: number;
    queueName?: AlertQueueName;
  } = {},
): QueueMetricSample {
  return {
    backlogBytes: options.backlogBytes ?? 128,
    backlogCount: options.backlogCount ?? 1,
    oldestMessageAgeSeconds: options.oldestMessageAgeSeconds ?? 1,
    queueName: options.queueName ?? "security_events_dlq",
    sampledAt,
  };
}

interface RuntimeMetricRow {
  backlog_bytes: number | null;
  backlog_count: number | null;
  component: string;
  consecutive_nonzero_samples: number | null;
  generation: number;
  lease_expires_at: string | null;
  lease_id: string | null;
  metric_sampled_at: string | null;
  nonzero_since_at: string | null;
  oldest_message_age_seconds: number | null;
  revision: number;
  status: string;
  updated_at: string;
}

async function runtimeRow(queueName: AlertQueueName): Promise<RuntimeMetricRow | null> {
  return env.PG72_ID_DB.prepare(
    `SELECT component, status, generation, revision, lease_id,
            lease_expires_at, metric_sampled_at,
            backlog_count, backlog_bytes, oldest_message_age_seconds,
            nonzero_since_at, consecutive_nonzero_samples, updated_at
       FROM alert_runtime_status
      WHERE component = ?`,
  )
    .bind(ALERT_QUEUE_COMPONENTS[queueName])
    .first<RuntimeMetricRow>();
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
          transform(await target.batch<Record<string, unknown>>(statements));
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

function failingBatchDatabase(): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return async () => {
          throw new Error(
            "Bearer private-token queue-message-id body=user@example.test",
          );
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function responseLossDatabase(): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          await target.batch<Record<string, unknown>>(statements);
          throw new Error(
            "response lost for private-token queue-message-id body=user@example.test",
          );
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function expectUnknown(result: Awaited<ReturnType<typeof readQueueMetricsAlertSource>>) {
  expect(result).toEqual({
    observation: {
      asOf: result.observation.asOf,
      dimension: result.observation.dimension,
      ruleId: "pgid.queue.dlq_approximate.v1",
      snapshot: {
        backlogBytes: null,
        backlogCount: null,
        consecutiveNonzeroSamples: null,
        nonzeroSinceAt: null,
        oldestMessageTimestamp: null,
        sampledAt: null,
      },
    },
    persistence: "unknown",
  });
  expect(evaluateAlertRule(result.observation)).toMatchObject({
    evidence: "unknown",
    severity: "none",
  });
}

beforeEach(async () => {
  await env.PG72_ID_DB.prepare(
    `DELETE FROM alert_runtime_status
      WHERE component IN (?, ?, ?, ?)`,
  )
    .bind(...QUEUE_COMPONENTS)
    .run();
});

describe.sequential("Queue metrics alert source repository", () => {
  it("persists every closed DLQ mapping and normalizes oldest age at promise completion", async () => {
    for (const [index, queueName] of ALERT_QUEUE_NAMES.entries()) {
      const sampledAt = at(BASE, index);
      const metrics = positiveMetrics(sampledAt, { ageMs: 1_999 });
      const result = await readQueueMetricsAlertSource(
        env.PG72_ID_DB,
        provider(metrics),
        { queueName },
        clock(sampledAt),
      );
      expect(result).toEqual({
        observation: {
          asOf: sampledAt,
          dimension: { kind: "queue", queue: queueName },
          ruleId: "pgid.queue.dlq_approximate.v1",
          snapshot: {
            backlogBytes: 128,
            backlogCount: 1,
            consecutiveNonzeroSamples: 1,
            nonzeroSinceAt: sampledAt,
            oldestMessageTimestamp: at(sampledAt, -1_000),
            sampledAt,
          },
        },
        persistence: "committed",
      });
      expect(await runtimeRow(queueName)).toMatchObject({
        backlog_bytes: 128,
        backlog_count: 1,
        component: ALERT_QUEUE_COMPONENTS[queueName],
        consecutive_nonzero_samples: 1,
        generation: 0,
        metric_sampled_at: sampledAt,
        nonzero_since_at: sampledAt,
        oldest_message_age_seconds: 1,
        revision: 0,
        status: "disabled",
        updated_at: sampledAt,
      });
      expect(evaluateAlertRule(result.observation)).toMatchObject({
        evidence: "known",
        selectedEvidence: { metricName: "depth", observedValue: 1 },
        severity: "warning",
      });
    }
    expect(Object.keys(ALERT_QUEUE_COMPONENTS).sort()).toEqual(
      [...ALERT_QUEUE_NAMES].sort(),
    );
  });

  it("mutates only the mapped Queue component and never the evaluator", async () => {
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_runtime_status (component, updated_at)
       VALUES ('evaluator', ?)`,
    ).bind(at(BASE, -1)).run();
    try {
      const before = await env.PG72_ID_DB.prepare(
        "SELECT * FROM alert_runtime_status WHERE component = 'evaluator'",
      ).first<Record<string, unknown>>();
      expect(await persistQueueMetricSample(env.PG72_ID_DB, sample(BASE)))
        .toMatchObject({ outcome: "committed" });
      const after = await env.PG72_ID_DB.prepare(
        "SELECT * FROM alert_runtime_status WHERE component = 'evaluator'",
      ).first<Record<string, unknown>>();
      expect(after).toEqual(before);
    } finally {
      await env.PG72_ID_DB.prepare(
        "DELETE FROM alert_runtime_status WHERE component = 'evaluator'",
      ).run();
    }
  });

  it("records canonical zero metrics without manufacturing a nonzero streak", async () => {
    const result = await readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      provider({ backlogBytes: 0, backlogCount: 0 }),
      { queueName: "security_events_dlq" },
      clock(BASE),
    );
    expect(result).toMatchObject({
      observation: {
        snapshot: {
          backlogBytes: 0,
          backlogCount: 0,
          consecutiveNonzeroSamples: 0,
          nonzeroSinceAt: null,
          oldestMessageTimestamp: null,
          sampledAt: BASE,
        },
      },
      persistence: "committed",
    });
    expect(evaluateAlertRule(result.observation)).toMatchObject({
      evidence: "known",
      severity: "none",
    });
  });

  it("increments only at exact 60-second cadence and resets after zero or a gap", async () => {
    const queueName = "logout_deliveries_dlq" as const;
    const first = await persistQueueMetricSample(
      env.PG72_ID_DB,
      sample(BASE, { queueName }),
    );
    expect(first).toMatchObject({
      outcome: "committed",
      snapshot: { consecutiveNonzeroSamples: 1, nonzeroSinceAt: BASE },
    });
    const secondAt = at(BASE, 60_000);
    const second = await persistQueueMetricSample(
      env.PG72_ID_DB,
      sample(secondAt, { queueName }),
    );
    expect(second).toMatchObject({
      outcome: "committed",
      snapshot: { consecutiveNonzeroSamples: 2, nonzeroSinceAt: BASE },
    });
    const zeroAt = at(BASE, 120_000);
    const zero = await persistQueueMetricSample(
      env.PG72_ID_DB,
      sample(zeroAt, {
        backlogBytes: 0,
        backlogCount: 0,
        oldestMessageAgeSeconds: 0,
        queueName,
      }),
    );
    expect(zero).toMatchObject({
      outcome: "committed",
      snapshot: { consecutiveNonzeroSamples: 0, nonzeroSinceAt: null },
    });
    const afterZeroAt = at(BASE, 180_000);
    expect(await persistQueueMetricSample(
      env.PG72_ID_DB,
      sample(afterZeroAt, { queueName }),
    )).toMatchObject({
      snapshot: { consecutiveNonzeroSamples: 1, nonzeroSinceAt: afterZeroAt },
    });
    const gapAt = at(afterZeroAt, 61_000);
    expect(await persistQueueMetricSample(
      env.PG72_ID_DB,
      sample(gapAt, { queueName }),
    )).toMatchObject({
      snapshot: { consecutiveNonzeroSamples: 1, nonzeroSinceAt: gapAt },
    });
    expect(await runtimeRow(queueName)).toMatchObject({
      metric_sampled_at: gapAt,
      revision: 4,
    });
  });

  it("requires both the persisted streak and fifteen elapsed minutes before critical", async () => {
    const queueName = "alert_deliveries_dlq" as const;
    let latest = await persistQueueMetricSample(
      env.PG72_ID_DB,
      sample(BASE, { backlogCount: 1, queueName }),
    );
    for (let minute = 1; minute < 15; minute += 1) {
      latest = await persistQueueMetricSample(
        env.PG72_ID_DB,
        sample(at(BASE, minute * 60_000), { backlogCount: 1, queueName }),
      );
    }
    expect(latest.snapshot?.consecutiveNonzeroSamples).toBe(15);
    const fifteenSamples = await readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      provider(positiveMetrics(at(BASE, 14 * 60_000))),
      { queueName },
      clock(at(BASE, 14 * 60_000)),
    );
    expect(fifteenSamples.persistence).toBe("replayed");
    expect(evaluateAlertRule(fifteenSamples.observation)).toMatchObject({
      evidence: "known",
      severity: "warning",
    });

    const sixteenthAt = at(BASE, 15 * 60_000);
    const sixteenth = await readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      provider(positiveMetrics(sixteenthAt)),
      { queueName },
      clock(sixteenthAt),
    );
    expect(sixteenth.observation.snapshot.consecutiveNonzeroSamples).toBe(16);
    expect(evaluateAlertRule(sixteenth.observation)).toMatchObject({
      evidence: "known",
      selectedEvidence: {
        metricName: "consecutive_nonzero_samples",
        observedValue: 15,
      },
      severity: "critical",
    });
  });

  it("treats exact duplicates as response-loss replays and rejects conflicts or stale samples", async () => {
    const firstSample = sample(BASE);
    expect(await persistQueueMetricSample(env.PG72_ID_DB, firstSample))
      .toMatchObject({ outcome: "committed" });
    expect(await persistQueueMetricSample(env.PG72_ID_DB, firstSample))
      .toMatchObject({ outcome: "replayed" });
    expect(await persistQueueMetricSample(
      env.PG72_ID_DB,
      { ...firstSample, backlogBytes: 129 },
    )).toEqual({ outcome: "rejected", snapshot: null });
    expect(await persistQueueMetricSample(
      env.PG72_ID_DB,
      { ...firstSample, sampledAt: at(BASE, -60_000) },
    )).toEqual({ outcome: "rejected", snapshot: null });
    expect(await runtimeRow("security_events_dlq")).toMatchObject({
      backlog_bytes: 128,
      metric_sampled_at: BASE,
      revision: 0,
    });
  });

  it("rejects an exact replay after a later unleased runtime transition", async () => {
    const current = sample(BASE);
    expect(await persistQueueMetricSample(env.PG72_ID_DB, current))
      .toMatchObject({ outcome: "committed" });
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET status = 'healthy', revision = revision + 1, updated_at = ?
        WHERE component = 'security_dlq'`,
    ).bind(at(BASE, 1)).run();

    expect(await persistQueueMetricSample(env.PG72_ID_DB, current)).toEqual({
      outcome: "rejected",
      snapshot: null,
    });
    const observed = await readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      provider(positiveMetrics(BASE)),
      { queueName: "security_events_dlq" },
      clock(BASE),
    );
    expectUnknown(observed);
    expect(await runtimeRow("security_events_dlq")).toMatchObject({
      lease_expires_at: null,
      lease_id: null,
      metric_sampled_at: BASE,
      revision: 1,
      status: "healthy",
      updated_at: at(BASE, 1),
    });
  });

  it("rejects an exact replay after a later lease retains the metrics", async () => {
    const current = sample(BASE);
    expect(await persistQueueMetricSample(env.PG72_ID_DB, current))
      .toMatchObject({ outcome: "committed" });
    const leaseId = crypto.randomUUID();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET generation = generation + 1,
              revision = revision + 1,
              lease_id = ?, lease_expires_at = ?, updated_at = ?
        WHERE component = 'security_dlq'`,
    ).bind(leaseId, at(BASE, 60_000), at(BASE, 1)).run();

    expect(await persistQueueMetricSample(env.PG72_ID_DB, current)).toEqual({
      outcome: "rejected",
      snapshot: null,
    });
    const observed = await readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      provider(positiveMetrics(BASE)),
      { queueName: "security_events_dlq" },
      clock(BASE),
    );
    expectUnknown(observed);
    expect(await runtimeRow("security_events_dlq")).toMatchObject({
      lease_expires_at: at(BASE, 60_000),
      lease_id: leaseId,
      metric_sampled_at: BASE,
      revision: 1,
      updated_at: at(BASE, 1),
    });
  });

  it("has one concurrent winner and classifies an exact loser as replay", async () => {
    const current = sample(BASE);
    const results = await Promise.all([
      persistQueueMetricSample(env.PG72_ID_DB, current),
      persistQueueMetricSample(env.PG72_ID_DB, current),
    ]);
    expect(results.map(({ outcome }) => outcome).sort()).toEqual([
      "committed",
      "replayed",
    ]);
    expect(await runtimeRow("security_events_dlq")).toMatchObject({ revision: 0 });
  });

  it("has one concurrent winner and fails a same-time contradictory loser closed", async () => {
    const results = await Promise.all([
      persistQueueMetricSample(env.PG72_ID_DB, sample(BASE)),
      persistQueueMetricSample(
        env.PG72_ID_DB,
        sample(BASE, { backlogBytes: 256, backlogCount: 2 }),
      ),
    ]);
    expect(results.map(({ outcome }) => outcome).sort()).toEqual([
      "committed",
      "rejected",
    ]);
    expect(await runtimeRow("security_events_dlq")).toMatchObject({ revision: 0 });
  });

  it("recovers an exact persisted sample after the D1 response is lost", async () => {
    const current = sample(BASE);
    const failed = persistQueueMetricSample(responseLossDatabase(), current);
    await expect(failed).rejects.toEqual(
      new AlertQueueSourceRepositoryError("write_failed"),
    );
    for (const marker of ["private-token", "queue-message-id", "user@example.test"]) {
      await expect(failed).rejects.not.toThrow(marker);
    }
    expect(await runtimeRow("security_events_dlq")).toMatchObject({
      lease_expires_at: null,
      lease_id: null,
      metric_sampled_at: BASE,
      revision: 0,
      updated_at: BASE,
    });
    expect(await persistQueueMetricSample(env.PG72_ID_DB, current)).toEqual({
      outcome: "replayed",
      snapshot: {
        backlogBytes: 128,
        backlogCount: 1,
        consecutiveNonzeroSamples: 1,
        nonzeroSinceAt: BASE,
        oldestMessageTimestamp: at(BASE, -1_000),
        sampledAt: BASE,
      },
    });
  });

  it("returns an unknown observation after response loss and a known replay on retry", async () => {
    const input = { queueName: "security_events_dlq" } as const;
    const metrics = positiveMetrics(BASE);
    const first = await readQueueMetricsAlertSource(
      responseLossDatabase(),
      provider(metrics),
      input,
      clock(BASE),
    );
    expectUnknown(first);
    const replay = await readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      provider(metrics),
      input,
      clock(BASE),
    );
    expect(replay).toMatchObject({
      observation: { snapshot: { sampledAt: BASE } },
      persistence: "replayed",
    });
  });

  it("calls the clock after the metrics promise settles", async () => {
    const order: string[] = [];
    const metricsProvider: QueueMetricsProvider = {
      async metrics() {
        order.push("metrics-start");
        await Promise.resolve();
        order.push("metrics-complete");
        return { backlogBytes: 0, backlogCount: 0 };
      },
    };
    await readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      metricsProvider,
      { queueName: "security_events_dlq" },
      () => {
        order.push("clock");
        return new Date(BASE);
      },
    );
    expect(order).toEqual(["metrics-start", "metrics-complete", "clock"]);
  });

  it("accepts exact caps and rejects unsafe, contradictory, or stale binding metrics", async () => {
    const capAgeMilliseconds = 1_000_000_000 * 1_000;
    const capResult = await readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      provider(positiveMetrics(BASE, {
        ageMs: capAgeMilliseconds,
        backlogBytes: 1_000_000_000_000,
        backlogCount: 1_000_000_000,
      })),
      { queueName: "security_events_dlq" },
      clock(BASE),
    );
    expect(capResult).toMatchObject({
      observation: {
        snapshot: {
          backlogBytes: 1_000_000_000_000,
          backlogCount: 1_000_000_000,
          oldestMessageTimestamp: at(BASE, -capAgeMilliseconds),
        },
      },
      persistence: "committed",
    });

    await env.PG72_ID_DB.prepare(
      "DELETE FROM alert_runtime_status WHERE component = 'security_dlq'",
    ).run();
    const invalidMetrics: unknown[] = [
      null,
      [],
      {},
      { backlogBytes: 0, backlogCount: 0, extra: "private-body" },
      { backlogBytes: "0", backlogCount: 0 },
      { backlogBytes: 0, backlogCount: "0" },
      { backlogBytes: 0, backlogCount: 0.5 },
      { backlogBytes: 0, backlogCount: -1 },
      { backlogBytes: 0, backlogCount: Number.NaN },
      { backlogBytes: 0, backlogCount: Number.POSITIVE_INFINITY },
      { backlogBytes: 0, backlogCount: 1_000_000_001 },
      { backlogBytes: 1_000_000_000_001, backlogCount: 1 },
      { backlogBytes: 1, backlogCount: 0 },
      {
        backlogBytes: 0,
        backlogCount: 0,
        oldestMessageTimestamp: new Date(BASE),
      },
      { backlogBytes: 1, backlogCount: 1 },
      {
        backlogBytes: 1,
        backlogCount: 1,
        oldestMessageTimestamp: null,
      },
      {
        backlogBytes: 1,
        backlogCount: 1,
        oldestMessageTimestamp: new Date(Number.NaN),
      },
      {
        backlogBytes: 1,
        backlogCount: 1,
        oldestMessageTimestamp: new Date(at(BASE, 1)),
      },
      positiveMetrics(BASE, { ageMs: capAgeMilliseconds + 1_000 }),
    ];
    for (const value of invalidMetrics) {
      const result = await readQueueMetricsAlertSource(
        env.PG72_ID_DB,
        provider(value),
        { queueName: "security_events_dlq" },
        clock(BASE),
      );
      expectUnknown(result);
      expect(await runtimeRow("security_events_dlq")).toBeNull();
    }
  });

  it("turns provider and D1 failures into redacted unknown observations", async () => {
    const rejectingProvider: QueueMetricsProvider = {
      async metrics() {
        throw new Error(
          "Bearer private-token queue-message-id body=user@example.test",
        );
      },
    };
    expectUnknown(await readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      rejectingProvider,
      { queueName: "security_events_dlq" },
      clock(BASE),
    ));
    expectUnknown(await readQueueMetricsAlertSource(
      failingBatchDatabase(),
      provider(positiveMetrics(BASE)),
      { queueName: "security_events_dlq" },
      clock(BASE),
    ));
  });

  it("rejects invalid inputs and redacts clock failures", async () => {
    const metricsProvider = provider({ backlogBytes: 0, backlogCount: 0 });
    await expect(readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      metricsProvider,
      { queueName: "not-a-queue" as AlertQueueName },
      clock(BASE),
    )).rejects.toEqual(new AlertQueueSourceRepositoryError("invalid_input"));
    expect(metricsProvider.metrics).not.toHaveBeenCalled();

    await expect(readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      provider({ backlogBytes: 0, backlogCount: 0 }),
      { queueName: "security_events_dlq" },
      () => new Date(Number.NaN),
    )).rejects.toEqual(new AlertQueueSourceRepositoryError("source_invalid"));
    const clockFailure = readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      provider({ backlogBytes: 0, backlogCount: 0 }),
      { queueName: "security_events_dlq" },
      () => {
        throw new Error(
          "Bearer private-token queue-message-id body=user@example.test",
        );
      },
    );
    await expect(clockFailure).rejects.toEqual(
      new AlertQueueSourceRepositoryError("source_unavailable"),
    );
    for (const marker of ["private-token", "queue-message-id", "user@example.test"]) {
      await expect(clockFailure).rejects.not.toThrow(marker);
    }
  });

  it("rejects invalid persistence samples before touching D1", async () => {
    for (const invalid of [
      { ...sample(BASE), queueName: "wrong" },
      { ...sample(BASE), sampledAt: "not-a-time" },
      { ...sample(BASE), backlogCount: 1.5 },
      { ...sample(BASE), backlogBytes: -1 },
      {
        ...sample(BASE),
        backlogBytes: 1,
        backlogCount: 0,
        oldestMessageAgeSeconds: 0,
      },
    ]) {
      await expect(persistQueueMetricSample(
        env.PG72_ID_DB,
        invalid as QueueMetricSample,
      )).rejects.toEqual(new AlertQueueSourceRepositoryError("invalid_input"));
    }
    expect(await runtimeRow("security_events_dlq")).toBeNull();
  });

  it("keeps an older or same-clock sample unknown when component state is newer", async () => {
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_runtime_status (component, updated_at)
       VALUES ('security_dlq', ?)`,
    )
      .bind(at(BASE, 1))
      .run();
    const result = await readQueueMetricsAlertSource(
      env.PG72_ID_DB,
      provider(positiveMetrics(BASE)),
      { queueName: "security_events_dlq" },
      clock(BASE),
    );
    expectUnknown(result);
    expect(await runtimeRow("security_events_dlq")).toMatchObject({
      metric_sampled_at: null,
      revision: 0,
      updated_at: at(BASE, 1),
    });
  });

  it("initializes metrics on an existing unowned component row using revision CAS", async () => {
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_runtime_status (component, updated_at)
       VALUES ('security_dlq', ?)`,
    )
      .bind(at(BASE, -1))
      .run();
    expect(await persistQueueMetricSample(env.PG72_ID_DB, sample(BASE)))
      .toMatchObject({ outcome: "committed" });
    expect(await runtimeRow("security_events_dlq")).toMatchObject({
      metric_sampled_at: BASE,
      revision: 1,
    });
  });

  it("does not mutate a component row owned by an active lease", async () => {
    const leaseId = crypto.randomUUID();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_runtime_status (component, updated_at)
       VALUES ('security_dlq', ?)`,
    )
      .bind(at(BASE, -2))
      .run();
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET generation = 1, revision = 1, lease_id = ?,
              lease_expires_at = ?, updated_at = ?
        WHERE component = 'security_dlq'`,
    )
      .bind(leaseId, at(BASE, 60_000), at(BASE, -1))
      .run();
    expect(await persistQueueMetricSample(env.PG72_ID_DB, sample(BASE)))
      .toEqual({ outcome: "rejected", snapshot: null });
    expect(await runtimeRow("security_events_dlq")).toMatchObject({
      metric_sampled_at: null,
      revision: 1,
      updated_at: at(BASE, -1),
    });
  });

  it("strictly validates changes and projection rows without exposing source values", async () => {
    const privateMarker = "private-projection-marker";
    const variants: Array<(
      results: D1Result<Record<string, unknown>>[],
    ) => D1Result<Record<string, unknown>>[]> = [
      (results) => results.slice(0, 2),
      (results) => replaceResultRows(results, 1, [{ changed: "1" }]),
      (results) => replaceResultRows(results, 1, [{ changed: 1, extra: privateMarker }]),
      (results) => results.map((result, resultIndex) =>
        resultIndex === 0
          ? { ...result, meta: { ...result.meta, changes: 0 } }
          : result
      ),
      (results) => replaceResultRows(results, 2, []),
      (results) => replaceResultRows(results, 2, [{ private: privateMarker }]),
      (results) => replaceResultRows(results, 2, [{
        ...results[2]!.results[0],
        lease_id: crypto.randomUUID(),
        lease_expires_at: null,
      }]),
      (results) => replaceResultRows(results, 2, [{
        ...results[2]!.results[0],
        lease_id: null,
        lease_expires_at: at(BASE, 60_000),
      }]),
      (results) => replaceResultRows(results, 2, [{
        ...results[2]!.results[0],
        lease_id: privateMarker,
        lease_expires_at: at(BASE, 60_000),
      }]),
      (results) => replaceResultRows(results, 2, [{
        ...results[2]!.results[0],
        lease_id: crypto.randomUUID(),
        lease_expires_at: results[2]!.results[0]!.updated_at,
      }]),
      (results) => replaceResultRows(results, 2, [{
        ...results[2]!.results[0],
        backlog_count: 1.5,
      }]),
      (results) => replaceResultRows(results, 2, [{
        ...results[2]!.results[0],
        metric_sampled_at: "not-a-time",
      }]),
      (results) => replaceResultRows(results, 2, [{
        ...results[2]!.results[0],
        component: "private-component",
      }]),
    ];
    for (const [index, transform] of variants.entries()) {
      const queueName = ALERT_QUEUE_NAMES[index % ALERT_QUEUE_NAMES.length];
      await env.PG72_ID_DB.prepare(
        "DELETE FROM alert_runtime_status WHERE component = ?",
      ).bind(ALERT_QUEUE_COMPONENTS[queueName]).run();
      const failure = persistQueueMetricSample(
        transformBatchDatabase(transform),
        sample(at(BASE, index), { queueName }),
      );
      await expect(failure).rejects.toEqual(
        new AlertQueueSourceRepositoryError("source_invalid"),
      );
      await expect(failure).rejects.not.toThrow(privateMarker);
    }
  });

  it("uses the component primary-key index and keeps the source unwired", async () => {
    const plan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN ${ALERT_QUEUE_METRIC_PROJECTION_QUERY}`,
    )
      .bind("security_dlq")
      .all<{ detail: string }>();
    const detail = plan.results.map(({ detail }) => detail).join("\n");
    expect(detail).toContain("sqlite_autoindex_alert_runtime_status_1");
    expect(detail).toMatch(/SEARCH alert_runtime_status/);
    expect(ALERT_QUEUE_METRIC_SAMPLE_UPSERT).toContain(
      "alert_runtime_status.revision + 1",
    );
    expect(ALERT_QUEUE_METRIC_SAMPLE_UPSERT).toContain("'+60 seconds'");
    expect(ALERT_QUEUE_METRIC_SAMPLE_UPSERT).toContain(
      "alert_runtime_status.metric_sampled_at < excluded.metric_sampled_at",
    );
    expect(ALERT_QUEUE_METRIC_SAMPLE_UPSERT).toContain(
      "alert_runtime_status.lease_id IS NULL",
    );
    expect(ALERT_QUEUE_METRIC_CHANGES_QUERY).toBe(
      "SELECT changes() AS changed",
    );
  });
});
