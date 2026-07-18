import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

const CRON = "* * * * *";
const RUN_ID = "11111111-1111-4111-8111-111111111111";
const LEASE_ID = "22222222-2222-4222-8222-222222222222";
const DIGEST = "A".repeat(43);
const SOURCE_IDS = [
  "queue.security_events_dlq",
  "queue.logout_deliveries_dlq",
  "queue.alert_deliveries_dlq",
  "queue.audit_archive_dlq",
  "d1.audit",
  "d1.oauth_client_report",
  "d1.security_fanout_gap",
  "d1.logout_delivery",
  "d1.alert_runtime",
] as const;

function at(seconds: number): string {
  return new Date(Date.parse("2026-07-18T00:00:00.000Z") + seconds * 1_000)
    .toISOString();
}

async function initialize(): Promise<void> {
  await env.PG72_ID_DB.prepare(
    `INSERT INTO alert_runtime_status (component, updated_at)
     VALUES ('evaluator', ?)`,
  ).bind(at(0)).run();
}

async function acquireRun(): Promise<void> {
  await initialize();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO alert_evaluator_run
      (id, component, trigger_cron, trigger_scheduled_at,
       runtime_generation, acquired_revision, lease_revision, lease_id,
       started_at, lease_updated_at, lease_expires_at, status,
       created_at, updated_at)
     VALUES (?, 'evaluator', ?, ?, 1, 1, 1, ?, ?, ?, ?, 'running', ?, ?)`,
  ).bind(
    RUN_ID,
    CRON,
    at(60),
    LEASE_ID,
    at(60),
    at(60),
    at(180),
    at(60),
    at(60),
  ).run();
}

async function bindAsOf(): Promise<void> {
  await env.PG72_ID_DB.prepare(
    `UPDATE alert_evaluator_run
        SET as_of = ?, updated_at = ?
      WHERE id = ?`,
  ).bind(at(70), at(70), RUN_ID).run();
}

async function insertSources(
  partialSource: string | null = null,
): Promise<void> {
  for (const sourceId of SOURCE_IDS) {
    const partial = sourceId === partialSource;
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_evaluator_run_source
        (run_id, source_id, as_of, status, observation_count,
         incomplete_count, proof_sha256, runtime_generation,
         runtime_revision, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, ?)`,
    ).bind(
      RUN_ID,
      sourceId,
      at(70),
      partial ? "partial" : "complete",
      1,
      partial ? 1 : 0,
      DIGEST,
      at(71),
    ).run();
  }
}

async function seal(decisionCount = 0, partialCount = 0): Promise<void> {
  await env.PG72_ID_DB.prepare(
    `UPDATE alert_evaluator_run
        SET status = 'sealed', source_count = 9, partial_source_count = ?,
            source_manifest_sha256 = ?, decision_count = ?,
            decision_manifest_sha256 = ?, updated_at = ?
      WHERE id = ?`,
  ).bind(partialCount, DIGEST, decisionCount, DIGEST, at(72), RUN_ID).run();
}

async function runtime(): Promise<Record<string, unknown> | null> {
  return env.PG72_ID_DB.prepare(
    `SELECT generation, revision, lease_id, lease_expires_at, status,
            last_success_at, watermark_at, updated_at
       FROM alert_runtime_status WHERE component = 'evaluator'`,
  ).first<Record<string, unknown>>();
}

describe("alert evaluator run proof 0022 schema", () => {
  beforeEach(async () => {
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
      env.PG72_ID_DB.prepare("DROP TABLE IF EXISTS alert_evaluator_run_decision"),
      env.PG72_ID_DB.prepare("DROP TABLE IF EXISTS alert_evaluator_run_source"),
      env.PG72_ID_DB.prepare("DROP TABLE IF EXISTS alert_evaluator_run"),
      env.PG72_ID_DB.prepare("DELETE FROM alert_evaluator_bootstrap"),
      env.PG72_ID_DB.prepare("DELETE FROM alert_runtime_status"),
    ]);
    const migration = env.TEST_MIGRATIONS.find(
      ({ name }) => name === "0022_alert_evaluator_run_proof.sql",
    );
    if (!migration) throw new Error("missing run-proof migration");
    await env.PG72_ID_DB.batch(
      migration.queries.map((query) => env.PG72_ID_DB.prepare(query)),
    );
  });

  it("couples acquisition while preserving outer changes() semantics", async () => {
    await initialize();
    const results = await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_evaluator_run
          (id, component, trigger_cron, trigger_scheduled_at,
           runtime_generation, acquired_revision, lease_revision, lease_id,
           started_at, lease_updated_at, lease_expires_at, status,
           created_at, updated_at)
         VALUES (?, 'evaluator', ?, ?, 1, 1, 1, ?, ?, ?, ?, 'running', ?, ?)`,
      ).bind(
        RUN_ID,
        CRON,
        at(60),
        LEASE_ID,
        at(60),
        at(60),
        at(180),
        at(60),
        at(60),
      ),
      env.PG72_ID_DB.prepare("SELECT changes() AS changed"),
    ]);
    expect(results[0]?.meta.changes).toBe(2);
    expect(results[1]?.results).toEqual([{ changed: 1 }]);
    expect(await runtime()).toMatchObject({ generation: 1, revision: 1 });
  });

  it("atomically acquires through run insertion and rolls back a losing insert", async () => {
    await acquireRun();
    expect(await runtime()).toMatchObject({
      generation: 1,
      revision: 1,
      lease_id: LEASE_ID,
      status: "disabled",
    });

    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_evaluator_run
          (id, component, trigger_cron, trigger_scheduled_at,
           runtime_generation, acquired_revision, lease_revision, lease_id,
           started_at, lease_updated_at, lease_expires_at, status,
           created_at, updated_at)
         VALUES (?, 'evaluator', ?, ?, 2, 2, 2, ?, ?, ?, ?, 'running', ?, ?)`,
      ).bind(
        "33333333-3333-4333-8333-333333333333",
        CRON,
        at(61),
        "44444444-4444-4444-8444-444444444444",
        at(61),
        at(61),
        at(181),
        at(61),
        at(61),
      ).run(),
    ).rejects.toThrow();
    expect(await env.PG72_ID_DB.prepare(
      "SELECT count(*) AS count FROM alert_evaluator_run",
    ).first("count")).toBe(1);
    expect(await runtime()).toMatchObject({ generation: 1, revision: 1 });

    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO alert_evaluator_run
          (id, component, trigger_cron, trigger_scheduled_at,
           runtime_generation, acquired_revision, lease_revision, lease_id,
           started_at, lease_updated_at, lease_expires_at, status,
           created_at, updated_at)
         VALUES (?, 'evaluator', ?, ?, 1, 1, 1, ?, ?, ?, ?, 'running', ?, ?)`,
      ).bind(
        RUN_ID,
        CRON,
        at(60),
        LEASE_ID,
        at(60),
        at(60),
        at(180),
        at(60),
        at(60),
      ).run(),
    ).rejects.toThrow(/immutable/);
  });

  it("abandons only at exact expiry and rolls abandonment back on a CAS miss", async () => {
    await acquireRun();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_evaluator_run
          (id, component, trigger_cron, trigger_scheduled_at,
           runtime_generation, acquired_revision, lease_revision, lease_id,
           started_at, lease_updated_at, lease_expires_at, status,
           created_at, updated_at)
         VALUES (?, 'evaluator', ?, ?, 2, 3, 3, ?, ?, ?, ?, 'running', ?, ?)`,
      ).bind(
        "33333333-3333-4333-8333-333333333333",
        CRON,
        at(120),
        "44444444-4444-4444-8444-444444444444",
        at(180),
        at(180),
        at(300),
        at(180),
        at(180),
      ).run(),
    ).rejects.toThrow(/acquire exact runtime lease/);
    expect(await env.PG72_ID_DB.prepare(
      "SELECT status FROM alert_evaluator_run WHERE id = ?",
    ).bind(RUN_ID).first("status")).toBe("running");

    const result = await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_evaluator_run
        (id, component, trigger_cron, trigger_scheduled_at,
         runtime_generation, acquired_revision, lease_revision, lease_id,
         started_at, lease_updated_at, lease_expires_at, status,
         created_at, updated_at)
       VALUES (?, 'evaluator', ?, ?, 2, 2, 2, ?, ?, ?, ?, 'running', ?, ?)`,
    ).bind(
      "55555555-5555-4555-8555-555555555555",
      CRON,
      at(121),
      "66666666-6666-4666-8666-666666666666",
      at(180),
      at(180),
      at(300),
      at(180),
      at(180),
    ).run();
    expect(result.meta.changes).toBe(3);
    expect(await env.PG72_ID_DB.prepare(
      "SELECT status, completed_at FROM alert_evaluator_run WHERE id = ?",
    ).bind(RUN_ID).first()).toEqual({
      status: "abandoned",
      completed_at: at(180),
    });
    expect(await runtime()).toMatchObject({
      generation: 2,
      revision: 2,
      lease_id: "66666666-6666-4666-8666-666666666666",
    });
  });

  it("rejects every direct legacy acquire, renew, and idle terminal update", async () => {
    await initialize();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET generation = 1, revision = 1, lease_id = ?,
                lease_expires_at = ?, last_started_at = ?, updated_at = ?
          WHERE component = 'evaluator'`,
      ).bind(LEASE_ID, at(120), at(1), at(1)).run(),
    ).rejects.toThrow(/exact run proof/);

    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET status = 'healthy', revision = 1, last_started_at = ?,
                last_success_at = ?, watermark_at = ?, updated_at = ?
          WHERE component = 'evaluator'`,
      ).bind(at(1), at(2), at(1), at(2)).run(),
    ).rejects.toThrow(/idle evaluator runtime/);

    await env.PG72_ID_DB.prepare("DELETE FROM alert_runtime_status").run();
    await acquireRun();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET revision = 2, lease_expires_at = ?, updated_at = ?
          WHERE component = 'evaluator'`,
      ).bind(at(190), at(61)).run(),
    ).rejects.toThrow(/exact run proof/);
  });

  it("couples a running renewal and preserves changes()", async () => {
    await acquireRun();
    const results = await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `UPDATE alert_evaluator_run
            SET lease_revision = 2, lease_updated_at = ?,
                lease_expires_at = ?, updated_at = ?
          WHERE id = ? AND lease_revision = 1`,
      ).bind(at(61), at(190), at(61), RUN_ID),
      env.PG72_ID_DB.prepare("SELECT changes() AS changed"),
    ]);
    // D1 meta includes the outer run row plus the runtime row changed by the
    // AFTER trigger. SQLite changes() remains scoped to the outer statement.
    expect(results[0]?.meta.changes).toBe(2);
    expect(results[1]?.results).toEqual([{ changed: 1 }]);
    expect(await runtime()).toMatchObject({ revision: 2, updated_at: at(61) });

  });

  it("couples exact same-owner renewal after sealing", async () => {
    await acquireRun();
    await bindAsOf();
    await insertSources();
    await seal();
    const results = await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `UPDATE alert_evaluator_run
            SET lease_revision = 2, lease_updated_at = ?,
                lease_expires_at = ?, updated_at = ?
          WHERE id = ? AND status = 'sealed' AND lease_revision = 1`,
      ).bind(at(73), at(200), at(73), RUN_ID),
      env.PG72_ID_DB.prepare("SELECT changes() AS changed"),
    ]);
    expect(results[0]?.meta.changes).toBe(2);
    expect(results[1]?.results).toEqual([{ changed: 1 }]);
    expect(await runtime()).toMatchObject({
      revision: 2,
      lease_expires_at: at(200),
      updated_at: at(73),
    });
  });

  it("rejects invalid asOf/source chronology and sealing without exact proofs", async () => {
    await acquireRun();
    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE alert_evaluator_run SET as_of = ?, updated_at = ? WHERE id = ?",
      ).bind(at(59), at(70), RUN_ID).run(),
    ).rejects.toThrow(/invalid evaluator run transition/);
    await bindAsOf();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_evaluator_run_source
          (run_id, source_id, as_of, status, observation_count,
           incomplete_count, proof_sha256, runtime_generation,
           runtime_revision, recorded_at)
         VALUES (?, ?, ?, 'complete', 1, 0, ?, 1, 1, ?)`,
      ).bind(RUN_ID, SOURCE_IDS[0], at(70), DIGEST, at(69)).run(),
    ).rejects.toThrow(/exact live run/);
    await expect(seal()).rejects.toThrow(/invalid evaluator run transition/);

    await insertSources(SOURCE_IDS[0]);
    await expect(seal(0, 0)).rejects.toThrow(/invalid evaluator run transition/);
    await seal(0, 1);
  });

  it("uses base64url digests and rejects replacement of immutable proofs", async () => {
    await acquireRun();
    await bindAsOf();
    await insertSources();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO alert_evaluator_run_source
          (run_id, source_id, as_of, status, observation_count,
           incomplete_count, proof_sha256, runtime_generation,
           runtime_revision, recorded_at)
         VALUES (?, ?, ?, 'complete', 2, 0, ?, 1, 1, ?)`,
      ).bind(RUN_ID, SOURCE_IDS[0], at(70), DIGEST, at(71)).run(),
    ).rejects.toThrow(/immutable/);
    await expect(
      env.PG72_ID_DB.prepare(
        "DELETE FROM alert_evaluator_run_source WHERE run_id = ?",
      ).bind(RUN_ID).run(),
    ).rejects.toThrow(/immutable/);
    await expect(
      env.PG72_ID_DB.prepare(
        "DELETE FROM alert_evaluator_run WHERE id = ?",
      ).bind(RUN_ID).run(),
    ).rejects.toThrow(/immutable/);
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_evaluator_run
            SET status = 'sealed', source_count = 9, partial_source_count = 0,
                source_manifest_sha256 = ?, decision_count = 0,
                decision_manifest_sha256 = ?, updated_at = ?
          WHERE id = ?`,
      ).bind("a".repeat(64), DIGEST, at(72), RUN_ID).run(),
    ).rejects.toThrow();
  });

  it.each([
    ["unavailable", "metrics_unavailable"],
    ["failing", "evaluator_failed"],
    ["failing", "unknown"],
  ] as const)(
    "maps terminal %s to %s and exact readback",
    async (status, errorCode) => {
      await acquireRun();
      const result = await env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET status = ?, revision = 2, lease_id = NULL,
                lease_expires_at = NULL, last_error_at = ?,
                last_error_code = ?, updated_at = ?
          WHERE component = 'evaluator' AND generation = 1
            AND revision = 1 AND lease_id = ?`,
      ).bind(status, at(70), errorCode, at(70), LEASE_ID).run();
      expect(result.meta.changes).toBe(2);
      expect(await env.PG72_ID_DB.prepare(
        `SELECT status, failure_status, failure_error_code,
                terminal_runtime_revision
           FROM alert_evaluator_run WHERE id = ?`,
      ).bind(RUN_ID).first()).toEqual({
        status: "failed",
        failure_status: status,
        failure_error_code: errorCode,
        terminal_runtime_revision: 2,
      });
    },
  );

  it("attributes suppressed decisions to the exact partial source", async () => {
    await acquireRun();
    await bindAsOf();
    await insertSources(SOURCE_IDS[0]);
    await seal(1, 1);

    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_evaluator_run_decision
          (run_id, source_id, ordinal, identity_sha256, evaluation_sha256,
           decision_sha256, disposition, as_of, runtime_generation,
           runtime_revision, recorded_at)
         VALUES (?, ?, 0, ?, ?, ?, 'suppressed_partial', ?, 1, 1, ?)`,
      ).bind(
        RUN_ID,
        SOURCE_IDS[1],
        DIGEST,
        `E${"A".repeat(42)}`,
        `I${"A".repeat(42)}`,
        at(70),
        at(73),
      ).run(),
    ).rejects.toThrow(/exact live run result/);

    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_evaluator_run_decision
        (run_id, source_id, ordinal, identity_sha256, evaluation_sha256,
         decision_sha256, disposition, as_of, runtime_generation,
         runtime_revision, recorded_at)
       VALUES (?, ?, 0, ?, ?, ?, 'suppressed_partial', ?, 1, 1, ?)`,
    ).bind(
      RUN_ID,
      SOURCE_IDS[0],
      DIGEST,
      `E${"A".repeat(42)}`,
      `I${"A".repeat(42)}`,
      at(70),
      at(73),
    ).run();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO alert_evaluator_run_decision
          (run_id, source_id, ordinal, identity_sha256, evaluation_sha256,
           decision_sha256, disposition, as_of, runtime_generation,
           runtime_revision, recorded_at)
         VALUES (?, ?, 0, ?, ?, ?, 'suppressed_partial', ?, 1, 1, ?)`,
      ).bind(
        RUN_ID,
        SOURCE_IDS[0],
        DIGEST,
        `E${"A".repeat(42)}`,
        `I${"A".repeat(42)}`,
        at(70),
        at(74),
      ).run(),
    ).rejects.toThrow(/immutable/);

    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET status = 'healthy', revision = 2, lease_id = NULL,
                lease_expires_at = NULL, last_success_at = ?, watermark_at = ?,
                updated_at = ?
          WHERE component = 'evaluator'`,
      ).bind(at(75), at(70), at(75)).run(),
    ).rejects.toThrow(/exact run proof/);

    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET status = 'unavailable', revision = 2, lease_id = NULL,
                lease_expires_at = NULL, last_error_at = ?,
                last_error_code = 'source_incomplete', updated_at = ?
          WHERE component = 'evaluator'`,
      ).bind(at(75), at(75)).run(),
    ).rejects.toThrow(/exact run proof/);

    const results = await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET status = 'degraded', revision = 2, lease_id = NULL,
                lease_expires_at = NULL, last_error_at = ?,
                last_error_code = 'source_incomplete', updated_at = ?
          WHERE component = 'evaluator'`,
      ).bind(at(75), at(75)),
      env.PG72_ID_DB.prepare("SELECT changes() AS changed"),
    ]);
    expect(results[0]?.meta.changes).toBe(2);
    expect(results[1]?.results).toEqual([{ changed: 1 }]);
    expect(await env.PG72_ID_DB.prepare(
      `SELECT status, failure_status, failure_error_code
         FROM alert_evaluator_run WHERE id = ?`,
    ).bind(RUN_ID).first()).toEqual({
      status: "failed",
      failure_status: "degraded",
      failure_error_code: "source_incomplete",
    });

    const replay = await env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET status = 'degraded', revision = 2, lease_id = NULL,
              lease_expires_at = NULL, last_error_at = ?,
              last_error_code = 'source_incomplete', updated_at = ?
        WHERE component = 'evaluator' AND generation = 1
          AND revision = 1 AND lease_id = ?`,
    ).bind(at(75), at(75), LEASE_ID).run();
    expect(replay.meta.changes).toBe(0);
  });

  it("requires terminal success after all proof writes and forbids suppressed success", async () => {
    await acquireRun();
    await bindAsOf();
    await insertSources();
    await seal();
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET status = 'healthy', revision = 2, lease_id = NULL,
                lease_expires_at = NULL, last_success_at = ?, watermark_at = ?,
                updated_at = ?
          WHERE component = 'evaluator'`,
      ).bind(at(72), at(70), at(72)).run(),
    ).rejects.toThrow(/exact run proof/);

    const results = await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `UPDATE alert_runtime_status
            SET status = 'healthy', revision = 2, lease_id = NULL,
                lease_expires_at = NULL, last_success_at = ?, watermark_at = ?,
                updated_at = ?
          WHERE component = 'evaluator'`,
      ).bind(at(74), at(70), at(74)),
      env.PG72_ID_DB.prepare("SELECT changes() AS changed"),
    ]);
    // D1 meta includes the runtime row and terminalized run row.
    expect(results[0]?.meta.changes).toBe(2);
    expect(results[1]?.results).toEqual([{ changed: 1 }]);
    expect(await env.PG72_ID_DB.prepare(
      `SELECT status, completed_at, watermark_at, terminal_runtime_revision
         FROM alert_evaluator_run WHERE id = ?`,
    ).bind(RUN_ID).first()).toEqual({
      status: "succeeded",
      completed_at: at(74),
      watermark_at: at(70),
      terminal_runtime_revision: 2,
    });

    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT OR REPLACE INTO alert_evaluator_run
          (id, component, trigger_cron, trigger_scheduled_at,
           runtime_generation, acquired_revision, lease_revision, lease_id,
           started_at, lease_updated_at, lease_expires_at, status,
           created_at, updated_at)
         VALUES (?, 'evaluator', ?, ?, 2, 3, 3, ?, ?, ?, ?, 'running', ?, ?)`,
      ).bind(
        "77777777-7777-4777-8777-777777777777",
        CRON,
        at(60),
        "88888888-8888-4888-8888-888888888888",
        at(80),
        at(80),
        at(180),
        at(80),
        at(80),
      ).run(),
    ).rejects.toThrow(/immutable/);
  });

  it("indexes bounded status/expiry lookup and preserves foreign-key integrity", async () => {
    const indexes = await env.PG72_ID_DB.prepare(
      `SELECT name FROM sqlite_schema
        WHERE type = 'index' AND tbl_name = 'alert_evaluator_run'
        ORDER BY name`,
    ).all<{ name: string }>();
    expect(indexes.results.map(({ name }) => name)).toContain(
      "alert_evaluator_run_status_expiry_idx",
    );
    expect(
      await env.PG72_ID_DB.prepare("PRAGMA foreign_key_check").all(),
    ).toMatchObject({ results: [] });
  });

  it("rejects orphan proofs and parent removal with explicit FK fixtures", async () => {
    await acquireRun();
    await bindAsOf();

    await env.PG72_ID_DB.prepare(
      "DROP TRIGGER alert_evaluator_run_source_insert_guard",
    ).run();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_evaluator_run_source
          (run_id, source_id, as_of, status, observation_count,
           incomplete_count, proof_sha256, runtime_generation,
           runtime_revision, recorded_at)
         VALUES (?, ?, ?, 'complete', 1, 0, ?, 1, 1, ?)`,
      ).bind(
        "99999999-9999-4999-8999-999999999999",
        SOURCE_IDS[0],
        at(70),
        DIGEST,
        at(71),
      ).run(),
    ).rejects.toThrow(/FOREIGN KEY/);

    const migration = env.TEST_MIGRATIONS.find(
      ({ name }) => name === "0022_alert_evaluator_run_proof.sql",
    );
    const sourceGuard = migration?.queries.find((query) =>
      query.includes('CREATE TRIGGER "alert_evaluator_run_source_insert_guard"')
    );
    if (!sourceGuard) throw new Error("missing source insert guard query");
    await env.PG72_ID_DB.prepare(sourceGuard).run();
    await insertSources();
    await seal(1);

    await env.PG72_ID_DB.prepare(
      "DROP TRIGGER alert_evaluator_run_decision_insert_guard",
    ).run();
    await env.PG72_ID_DB.prepare(
      "DROP TRIGGER alert_evaluator_run_source_delete_guard",
    ).run();
    await env.PG72_ID_DB.prepare(
      "DELETE FROM alert_evaluator_run_source WHERE run_id = ? AND source_id = ?",
    ).bind(RUN_ID, SOURCE_IDS[0]).run();
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO alert_evaluator_run_decision
          (run_id, source_id, ordinal, identity_sha256, evaluation_sha256,
           decision_sha256, disposition, as_of, runtime_generation,
           runtime_revision, recorded_at)
         VALUES (?, ?, 0, ?, ?, ?, 'no_state_change', ?, 1, 1, ?)`,
      ).bind(
        RUN_ID,
        SOURCE_IDS[0],
        DIGEST,
        `E${"A".repeat(42)}`,
        `I${"A".repeat(42)}`,
        at(70),
        at(73),
      ).run(),
    ).rejects.toThrow(/FOREIGN KEY/);
    await expect(
      env.PG72_ID_DB.prepare(
        "DELETE FROM alert_evaluator_run WHERE id = ?",
      ).bind(RUN_ID).run(),
    ).rejects.toThrow(/immutable/);
  });
});
