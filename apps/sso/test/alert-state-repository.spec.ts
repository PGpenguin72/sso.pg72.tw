import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import {
  advanceAlertLifecycle,
  inactiveAlertState,
  type AlertLifecycleState,
} from "../worker/alert-evaluator";
import {
  AlertStateRepositoryError,
  persistAlertLifecycleDecision,
  readAlertLifecycleSnapshot,
  type AlertStateCasExpectation,
  type AlertStatePersistenceResult,
} from "../worker/alert-state-repository";
import {
  evaluateAlertRule,
  type AlertRuleEvaluation,
} from "../worker/alert-rules";

const T0 = new Date("2026-07-18T06:00:00.000Z").getTime();
const GLOBAL = { kind: "global" } as const;
const SUBJECT_REF = { keyVersion: 1, value: "A".repeat(43) } as const;
const SUBJECT = { kind: "subject_hmac", reference: SUBJECT_REF } as const;

function at(milliseconds: number): string {
  return new Date(T0 + milliseconds).toISOString();
}

function registrationObservation(
  asOf: string,
  severity: "critical" | "none" | "warning",
) {
  const windows = severity === "critical"
    ? { "5m": { count: 40 }, "15m": { count: 40 }, "60m": { count: 40 } }
    : severity === "warning"
      ? { "5m": { count: 5 }, "15m": { count: 5 }, "60m": { count: 5 } }
      : { "5m": { count: 0 }, "15m": { count: 0 }, "60m": { count: 0 } };
  return {
    asOf,
    dimension: GLOBAL,
    ruleId: "pgid.registration.rate_limited.v1",
    windows,
  } as const;
}

function runtimeImmediateObservation(asOf: string) {
  return {
    asOf,
    dimension: GLOBAL,
    ruleId: "pgid.alert.runtime_health.v1",
    snapshot: {
      deadOutbox: 1,
      evaluatorAgeSeconds: 0,
      outboxDueAgeSeconds: null,
    },
  } as const;
}

function fanoutObservation(asOf: string, missing: number) {
  return {
    asOf,
    dimension: GLOBAL,
    ruleId: "pgid.security.fanout_gap.v1",
    snapshot: {
      missingOlderThan15mCount: 0,
      missingOlderThan5mCount: missing,
    },
  } as const;
}

function queueObservation(asOf: string, known: boolean) {
  return {
    asOf,
    dimension: { kind: "queue", queue: "alert_deliveries_dlq" },
    ruleId: "pgid.queue.dlq_approximate.v1",
    snapshot: known
      ? {
          backlogBytes: 10,
          backlogCount: 1,
          consecutiveNonzeroSamples: 1,
          nonzeroSinceAt: asOf,
          oldestMessageTimestamp: asOf,
          sampledAt: asOf,
        }
      : {
          backlogBytes: null,
          backlogCount: null,
          consecutiveNonzeroSamples: null,
          nonzeroSinceAt: null,
          oldestMessageTimestamp: null,
          sampledAt: null,
        },
  } as const;
}

function restrictedCriticalObservation(asOf: string) {
  return {
    asOf,
    dimension: SUBJECT,
    ruleId: "pgid.restricted.sensitive_denied.v1",
    windows: {
      "5m": { count: 5, knownSurfaces: 2 },
      "15m": { count: 5, knownSurfaces: 2 },
      "60m": { count: 5, knownSurfaces: 2 },
    },
  } as const;
}

interface StepResult {
  decision: ReturnType<typeof advanceAlertLifecycle>;
  evaluation: AlertRuleEvaluation;
  result: AlertStatePersistenceResult;
}

async function persistStep(
  database: D1Database,
  previous: AlertLifecycleState,
  observation: unknown,
  expected: AlertStateCasExpectation | null,
): Promise<StepResult> {
  const evaluation = evaluateAlertRule(observation);
  const decision = advanceAlertLifecycle({
    asOf: evaluation.asOf,
    observation,
    previous,
  });
  const result = await persistAlertLifecycleDecision(database, {
    decision,
    environment: "local",
    evaluation,
    expected,
  });
  return { decision, evaluation, result };
}

interface ExpectationRow {
  generation: number;
  incident_id: string | null;
  incident_status: "acknowledged" | "open" | null;
  last_evaluated_at: string;
  revision: number;
  state_id: string;
}

async function currentExpectation(): Promise<AlertStateCasExpectation> {
  const row = await env.PG72_ID_DB.prepare(
    `SELECT s.id AS state_id, s.generation, s.revision, s.last_evaluated_at,
            a.id AS incident_id, a.status AS incident_status
       FROM alert_state AS s
       LEFT JOIN security_alert AS a
         ON a.state_id = s.id AND a.status IN ('open', 'acknowledged')`,
  ).first<ExpectationRow>();
  if (row === null) throw new Error("expected persisted alert state");
  return {
    generation: row.generation,
    incident: row.incident_id === null || row.incident_status === null
      ? null
      : { id: row.incident_id, status: row.incident_status },
    lastEvaluatedAt: row.last_evaluated_at,
    revision: row.revision,
    stateId: row.state_id,
  };
}

async function tableCount(table: "alert_outbox" | "alert_state" | "security_alert") {
  return await env.PG72_ID_DB.prepare(`SELECT count(*) AS count FROM ${table}`)
    .first<number>("count");
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function rollbackProbeDatabase(): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return (statements: D1PreparedStatement[]) => target.batch([
          ...statements,
          target.prepare("INSERT INTO alert_state (id) VALUES (?)").bind("bad"),
        ]);
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function snapshotProjectionDatabase(
  transform: (results: D1Result[]) => D1Result[],
): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) =>
          transform(await target.batch(statements));
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function registrationSnapshot(database: D1Database = env.PG72_ID_DB) {
  return readAlertLifecycleSnapshot(database, {
    dimension: GLOBAL,
    environment: "local",
    ruleId: "pgid.registration.rate_limited.v1",
  });
}

describe.sequential("alert state CAS repository", () => {
  beforeEach(async () => {
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare("DELETE FROM alert_delivery_attempt"),
      env.PG72_ID_DB.prepare("DELETE FROM alert_outbox"),
      env.PG72_ID_DB.prepare("DELETE FROM security_alert"),
      env.PG72_ID_DB.prepare("DELETE FROM alert_state"),
    ]);
  });

  it("persists a first candidate, opens on the second breach, and deduplicates replay", async () => {
    expect(await registrationSnapshot()).toEqual({
      expected: null,
      previous: inactiveAlertState(),
    });
    const first = await persistStep(
      env.PG72_ID_DB,
      inactiveAlertState(),
      registrationObservation(at(0), "warning"),
      null,
    );
    expect(first.result).toBe("applied");
    expect(first.decision.state.phase).toBe("pending");
    expect(await registrationSnapshot()).toEqual({
      expected: await currentExpectation(),
      previous: first.decision.state,
    });

    const duplicate = await persistAlertLifecycleDecision(env.PG72_ID_DB, {
      decision: first.decision,
      environment: "local",
      evaluation: first.evaluation,
      expected: null,
    });
    expect(duplicate).toBe("duplicate");
    expect(await tableCount("alert_state")).toBe(1);
    expect(await tableCount("security_alert")).toBe(0);

    const pendingExpectation = await currentExpectation();
    const second = await persistStep(
      env.PG72_ID_DB,
      first.decision.state,
      registrationObservation(at(1), "warning"),
      pendingExpectation,
    );
    expect(second.result).toBe("applied");
    expect(second.decision.intent?.kind).toBe("open");
    expect(await tableCount("security_alert")).toBe(1);
    expect(await tableCount("alert_outbox")).toBe(1);
    expect(await registrationSnapshot()).toEqual({
      expected: await currentExpectation(),
      previous: second.decision.state,
    });

    const secondReplay = await persistAlertLifecycleDecision(env.PG72_ID_DB, {
      decision: second.decision,
      environment: "local",
      evaluation: second.evaluation,
      expected: pendingExpectation,
    });
    expect(secondReplay).toBe("duplicate");
    expect(await tableCount("alert_outbox")).toBe(1);
  });

  it("lets exactly one stale revision win without partial incident work", async () => {
    const first = await persistStep(
      env.PG72_ID_DB,
      inactiveAlertState(),
      registrationObservation(at(10), "warning"),
      null,
    );
    const expected = await currentExpectation();
    const openObservation = registrationObservation(at(11), "warning");
    const criticalObservation = registrationObservation(at(11), "critical");
    const openEvaluation = evaluateAlertRule(openObservation);
    const criticalEvaluation = evaluateAlertRule(criticalObservation);
    const openDecision = advanceAlertLifecycle({
      asOf: at(11),
      observation: openObservation,
      previous: first.decision.state,
    });
    const criticalDecision = advanceAlertLifecycle({
      asOf: at(11),
      observation: criticalObservation,
      previous: first.decision.state,
    });
    const results = await Promise.all([
      persistAlertLifecycleDecision(env.PG72_ID_DB, {
        decision: openDecision,
        environment: "local",
        evaluation: openEvaluation,
        expected,
      }),
      persistAlertLifecycleDecision(env.PG72_ID_DB, {
        decision: criticalDecision,
        environment: "local",
        evaluation: criticalEvaluation,
        expected,
      }),
    ]);
    expect(results.toSorted()).toEqual(["applied", "conflict"]);
    const state = await env.PG72_ID_DB.prepare(
      "SELECT revision, current_severity FROM alert_state",
    ).first<{ current_severity: string; revision: number }>();
    expect(state?.revision).toBe(1);
    const incidents = await tableCount("security_alert");
    expect([0, 1]).toContain(incidents);
    expect(await tableCount("alert_outbox")).toBe(incidents);
  });

  it("reads acknowledged state and rejects mismatched or ambiguous incidents", async () => {
    const first = await persistStep(
      env.PG72_ID_DB,
      inactiveAlertState(),
      registrationObservation(at(40), "warning"),
      null,
    );
    const opened = await persistStep(
      env.PG72_ID_DB,
      first.decision.state,
      registrationObservation(at(41), "warning"),
      await currentExpectation(),
    );
    const operatorRef = "Q".repeat(42) + "A";
    await env.PG72_ID_DB.prepare(
      `UPDATE security_alert
          SET status = 'acknowledged', acknowledged_at = ?,
              acknowledged_by_ref = ?, acknowledged_by_hash_version = 1,
              updated_at = ?
        WHERE status = 'open'`,
    ).bind(at(42), operatorRef, at(42)).run();
    expect(await registrationSnapshot()).toEqual({
      expected: await currentExpectation(),
      previous: opened.decision.state,
    });

    const corruptIncident = (
      mutate: (row: Record<string, unknown>) => Record<string, unknown>,
    ) => snapshotProjectionDatabase((results) => {
      const incident = results[1]?.results[0];
      if (!incident) throw new Error("expected incident projection");
      results[1].results[0] = mutate(incident as Record<string, unknown>);
      return results;
    });
    await expect(registrationSnapshot(corruptIncident((row) => ({
      ...row,
      observed_value: Number(row.observed_value) + 1,
    })))).rejects.toEqual(new AlertStateRepositoryError("source_invalid"));
    await expect(registrationSnapshot(corruptIncident((row) => ({
      ...row,
      last_seen_at: at(43),
    })))).rejects.toEqual(new AlertStateRepositoryError("source_invalid"));
    await expect(registrationSnapshot(snapshotProjectionDatabase((results) => {
      const state = results[0]?.results[0];
      if (!state) throw new Error("expected state projection");
      results[0].results[0] = {
        ...(state as Record<string, unknown>),
        dedupe_key: "B".repeat(43),
      };
      return results;
    }))).rejects.toEqual(new AlertStateRepositoryError("source_invalid"));
    await expect(registrationSnapshot(snapshotProjectionDatabase((results) => {
      const incident = results[1]?.results[0];
      if (!incident) throw new Error("expected incident projection");
      results[1].results.push({
        ...(incident as Record<string, unknown>),
        id: crypto.randomUUID(),
      });
      return results;
    }))).rejects.toEqual(new AlertStateRepositoryError("source_invalid"));
  });

  it("opens immediate critical atomically and verifies canonical payload identity", async () => {
    const step = await persistStep(
      env.PG72_ID_DB,
      inactiveAlertState(),
      runtimeImmediateObservation(at(20)),
      null,
    );
    expect(step.result).toBe("applied");
    const state = await env.PG72_ID_DB.prepare(
      `SELECT generation, revision, current_severity, created_at,
              last_evaluated_at FROM alert_state`,
    ).first<{
      created_at: string;
      current_severity: string;
      generation: number;
      last_evaluated_at: string;
      revision: number;
    }>();
    expect(state).toEqual({
      created_at: at(19),
      current_severity: "critical",
      generation: 1,
      last_evaluated_at: at(20),
      revision: 1,
    });
    const delivery = await env.PG72_ID_DB.prepare(
      `SELECT delivery_key, idempotency_key, payload_json, payload_sha256
         FROM alert_outbox`,
    ).first<{
      delivery_key: string;
      idempotency_key: string;
      payload_json: string;
      payload_sha256: string;
    }>();
    expect(delivery).not.toBeNull();
    expect(delivery?.delivery_key).toMatch(/^pgid_ad_[A-Za-z0-9_-]{43}$/);
    expect(delivery?.idempotency_key).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await sha256Hex(delivery!.payload_json)).toBe(delivery?.payload_sha256);
    expect(JSON.parse(delivery!.payload_json)).toMatchObject({
      eventKind: "opened",
      generation: 1,
      severity: "critical",
      status: "open",
    });
    expect(
      await persistAlertLifecycleDecision(env.PG72_ID_DB, {
        decision: step.decision,
        environment: "local",
        evaluation: step.evaluation,
        expected: null,
      }),
    ).toBe("duplicate");
    expect(await tableCount("security_alert")).toBe(1);
    expect(await tableCount("alert_outbox")).toBe(1);
  });

  it("resolves only on the fifth clear and keeps a non-sliding cooldown", async () => {
    const first = await persistStep(
      env.PG72_ID_DB,
      inactiveAlertState(),
      registrationObservation(at(100), "warning"),
      null,
    );
    let current = await persistStep(
      env.PG72_ID_DB,
      first.decision.state,
      registrationObservation(at(101), "warning"),
      await currentExpectation(),
    );
    let resolveExpectation: AlertStateCasExpectation | null = null;
    for (let count = 1; count <= 5; count += 1) {
      const expectation = await currentExpectation();
      current = await persistStep(
        env.PG72_ID_DB,
        current.decision.state,
        registrationObservation(at(101 + count), "none"),
        expectation,
      );
      if (count < 5) {
        expect(current.decision.state.status).toBe("warning");
      } else {
        resolveExpectation = expectation;
      }
    }
    expect(current.decision.intent?.kind).toBe("resolve");
    expect(current.decision.state.cooldownUntil).toBe(at(106 + 30 * 60 * 1_000));
    expect(resolveExpectation).not.toBeNull();
    expect(
      await persistAlertLifecycleDecision(env.PG72_ID_DB, {
        decision: current.decision,
        environment: "local",
        evaluation: current.evaluation,
        expected: resolveExpectation,
      }),
    ).toBe("duplicate");
    const persisted = await env.PG72_ID_DB.prepare(
      `SELECT s.current_severity, s.cooldown_until, a.status, a.resolution_code
         FROM alert_state AS s JOIN security_alert AS a ON a.state_id = s.id`,
    ).first<{
      cooldown_until: string;
      current_severity: string;
      resolution_code: string;
      status: string;
    }>();
    expect(persisted).toEqual({
      cooldown_until: at(106 + 30 * 60 * 1_000),
      current_severity: "none",
      resolution_code: "healthy",
      status: "resolved",
    });
    expect(await registrationSnapshot()).toEqual({
      expected: await currentExpectation(),
      previous: current.decision.state,
    });
    await expect(registrationSnapshot(snapshotProjectionDatabase((results) => {
      const incident = results[1]?.results[0];
      if (!incident) throw new Error("expected resolved incident projection");
      results[1].results[0] = {
        ...(incident as Record<string, unknown>),
        last_seen_at: at(107),
      };
      return results;
    }))).rejects.toEqual(new AlertStateRepositoryError("source_invalid"));
    expect(await tableCount("alert_outbox")).toBe(2);

    let blocked = await persistStep(
      env.PG72_ID_DB,
      current.decision.state,
      registrationObservation(at(107), "warning"),
      await currentExpectation(),
    );
    blocked = await persistStep(
      env.PG72_ID_DB,
      blocked.decision.state,
      registrationObservation(at(108), "warning"),
      await currentExpectation(),
    );
    expect(blocked.decision.state.status).toBe("none");
    expect(blocked.decision.state.consecutiveBreaches).toBe(1);
    expect(await tableCount("security_alert")).toBe(1);

    const reopened = await persistStep(
      env.PG72_ID_DB,
      blocked.decision.state,
      registrationObservation(at(106 + 30 * 60 * 1_000), "warning"),
      await currentExpectation(),
    );
    expect(reopened.decision.intent?.kind).toBe("open");
    expect(reopened.decision.state.cooldownUntil).toBeNull();
    expect(await tableCount("security_alert")).toBe(2);
    expect(await tableCount("alert_outbox")).toBe(3);
  });

  it("escalates warning to critical and keeps reminder sequences contiguous", async () => {
    const first = await persistStep(
      env.PG72_ID_DB,
      inactiveAlertState(),
      registrationObservation(at(500), "warning"),
      null,
    );
    let current = await persistStep(
      env.PG72_ID_DB,
      first.decision.state,
      registrationObservation(at(501), "warning"),
      await currentExpectation(),
    );
    current = await persistStep(
      env.PG72_ID_DB,
      current.decision.state,
      registrationObservation(at(502), "critical"),
      await currentExpectation(),
    );
    expect(current.decision.intent).toBeNull();
    expect(current.decision.state.status).toBe("warning");
    expect(current.decision.state.breachSeverity).toBe("critical");
    expect(await registrationSnapshot()).toEqual({
      expected: await currentExpectation(),
      previous: current.decision.state,
    });

    current = await persistStep(
      env.PG72_ID_DB,
      current.decision.state,
      registrationObservation(at(503), "critical"),
      await currentExpectation(),
    );
    expect(current.decision.intent?.kind).toBe("escalate");
    expect(current.decision.state.status).toBe("critical");

    let reminderIndex = 0;
    for (const reminderAt of [
      at(503 + 15 * 60 * 1_000),
      at(503 + 30 * 60 * 1_000),
    ]) {
      const reminderExpectation = await currentExpectation();
      const reminder = await persistStep(
        env.PG72_ID_DB,
        current.decision.state,
        registrationObservation(reminderAt, "critical"),
        reminderExpectation,
      );
      current = reminder;
      expect(current.decision.intent?.kind).toBe("remind");
      if (reminderIndex === 0) {
        expect(
          await persistAlertLifecycleDecision(env.PG72_ID_DB, {
            decision: reminder.decision,
            environment: "local",
            evaluation: reminder.evaluation,
            expected: reminderExpectation,
          }),
        ).toBe("duplicate");
      }
      reminderIndex += 1;
    }
    const reminders = await env.PG72_ID_DB.prepare(
      `SELECT event_sequence, severity, payload_json
         FROM alert_outbox
        WHERE event_kind = 'reminder'
        ORDER BY event_sequence`,
    ).all<{ event_sequence: number; payload_json: string; severity: string }>();
    expect(reminders.results.map(({ event_sequence }) => event_sequence))
      .toEqual([1, 2]);
    expect(reminders.results.every(({ severity }) => severity === "critical"))
      .toBe(true);
    expect(reminders.results.map(({ payload_json }) =>
      JSON.parse(payload_json).eventSequence
    )).toEqual([1, 2]);
  });

  it("keeps manual-only fanout active across healthy observations", async () => {
    const first = await persistStep(
      env.PG72_ID_DB,
      inactiveAlertState(),
      fanoutObservation(at(200), 1),
      null,
    );
    let current = await persistStep(
      env.PG72_ID_DB,
      first.decision.state,
      fanoutObservation(at(201), 1),
      await currentExpectation(),
    );
    for (let index = 1; index <= 6; index += 1) {
      current = await persistStep(
        env.PG72_ID_DB,
        current.decision.state,
        fanoutObservation(at(201 + index), 0),
        await currentExpectation(),
      );
    }
    expect(current.decision.state.status).toBe("warning");
    expect(current.decision.state.consecutiveClears).toBe(0);
    expect(current.decision.intent).toBeNull();
    expect(
      await env.PG72_ID_DB.prepare("SELECT status FROM security_alert")
        .first<string>("status"),
    ).toBe("open");
  });

  it("advances unknown evidence without silently clearing an active incident", async () => {
    const first = await persistStep(
      env.PG72_ID_DB,
      inactiveAlertState(),
      queueObservation(at(300), true),
      null,
    );
    const opened = await persistStep(
      env.PG72_ID_DB,
      first.decision.state,
      queueObservation(at(301), true),
      await currentExpectation(),
    );
    const unknown = await persistStep(
      env.PG72_ID_DB,
      opened.decision.state,
      queueObservation(at(302), false),
      await currentExpectation(),
    );
    expect(unknown.evaluation.evidence).toBe("unknown");
    expect(unknown.decision.state.status).toBe("warning");
    expect(unknown.result).toBe("applied");
    expect(
      await env.PG72_ID_DB.prepare("SELECT current_severity FROM alert_state")
        .first<string>("current_severity"),
    ).toBe("warning");
    expect(await tableCount("security_alert")).toBe(1);
  });

  it("persists only redacted HMAC dimensions and exact secondary evidence", async () => {
    const observation = restrictedCriticalObservation(at(350));
    const evaluation = evaluateAlertRule(observation);
    const decision = advanceAlertLifecycle({
      asOf: at(350),
      observation,
      previous: inactiveAlertState(),
    });
    const rawIdentity = "private-user@example.test";
    await expect(
      Reflect.apply(persistAlertLifecycleDecision, undefined, [
        env.PG72_ID_DB,
        {
          decision,
          environment: "local",
          evaluation,
          expected: null,
          rawIdentity,
        },
      ]),
    ).rejects.toEqual(new AlertStateRepositoryError("invalid_input"));

    const first = await persistStep(
      env.PG72_ID_DB,
      inactiveAlertState(),
      observation,
      null,
    );
    expect(first.evaluation.severity).toBe("critical");
    const opened = await persistStep(
      env.PG72_ID_DB,
      first.decision.state,
      restrictedCriticalObservation(at(351)),
      await currentExpectation(),
    );
    expect(opened.decision.intent?.kind).toBe("open");
    const persisted = await env.PG72_ID_DB.prepare(
      `SELECT s.subject_ref, s.hash_version, s.secondary_metric_name,
              s.secondary_observed_value, s.secondary_threshold,
              o.payload_json
         FROM alert_state AS s
         JOIN security_alert AS a ON a.state_id = s.id
         JOIN alert_outbox AS o ON o.alert_id = a.id`,
    ).first<{
      hash_version: number;
      payload_json: string;
      secondary_metric_name: string;
      secondary_observed_value: number;
      secondary_threshold: number;
      subject_ref: string;
    }>();
    expect(persisted).toMatchObject({
      hash_version: 1,
      secondary_metric_name: "known_surfaces",
      secondary_observed_value: 2,
      secondary_threshold: 2,
      subject_ref: SUBJECT_REF.value,
    });
    expect(persisted?.payload_json).not.toContain(rawIdentity);
    expect(JSON.parse(persisted!.payload_json)).toMatchObject({
      secondaryMetricName: "known_surfaces",
      secondaryObservedValue: 2,
      secondaryThreshold: 2,
      subjectRef: SUBJECT_REF.value,
    });
  });

  it("rolls the whole D1 batch back when a later trigger-bound write fails", async () => {
    await expect(
      persistStep(
        rollbackProbeDatabase(),
        inactiveAlertState(),
        registrationObservation(at(400), "warning"),
        null,
      ),
    ).rejects.toEqual(new AlertStateRepositoryError("write_failed"));
    expect(await tableCount("alert_state")).toBe(0);
    expect(await tableCount("security_alert")).toBe(0);
    expect(await tableCount("alert_outbox")).toBe(0);
  });
});
