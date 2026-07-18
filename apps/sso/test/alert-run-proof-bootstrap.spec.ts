import { env } from "cloudflare:workers";
import { expect, it } from "vitest";

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

it("commits first success with run/runtime/bootstrap or rolls all of it back", async () => {
  await env.PG72_ID_DB.prepare(
    `INSERT INTO alert_runtime_status (component, updated_at)
     VALUES ('evaluator', ?)`,
  ).bind(at(0)).run();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO alert_evaluator_run
      (id, component, trigger_cron, trigger_scheduled_at,
       runtime_generation, acquired_revision, lease_revision, lease_id,
       started_at, lease_updated_at, lease_expires_at, status,
       created_at, updated_at)
     VALUES (?, 'evaluator', '* * * * *', ?, 1, 1, 1, ?, ?, ?, ?,
             'running', ?, ?)`,
  ).bind(
    RUN_ID,
    at(60),
    LEASE_ID,
    at(60),
    at(60),
    at(180),
    at(60),
    at(60),
  ).run();
  await env.PG72_ID_DB.prepare(
    "UPDATE alert_evaluator_run SET as_of = ?, updated_at = ? WHERE id = ?",
  ).bind(at(70), at(70), RUN_ID).run();
  for (const sourceId of SOURCE_IDS) {
    await env.PG72_ID_DB.prepare(
      `INSERT INTO alert_evaluator_run_source
        (run_id, source_id, as_of, status, observation_count,
         incomplete_count, proof_sha256, runtime_generation,
         runtime_revision, recorded_at)
       VALUES (?, ?, ?, 'complete', 1, 0, ?, 1, 1, ?)`,
    ).bind(RUN_ID, sourceId, at(70), DIGEST, at(71)).run();
  }
  await env.PG72_ID_DB.prepare(
    `UPDATE alert_evaluator_run
        SET status = 'sealed', source_count = 9, partial_source_count = 0,
            source_manifest_sha256 = ?, decision_count = 0,
            decision_manifest_sha256 = ?, updated_at = ?
      WHERE id = ?`,
  ).bind(DIGEST, DIGEST, at(72), RUN_ID).run();

  await expect(env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET status = 'healthy', revision = 2, lease_id = NULL,
              lease_expires_at = NULL, last_success_at = ?, watermark_at = ?,
              updated_at = ?
        WHERE component = 'evaluator' AND generation = 1
          AND revision = 1 AND lease_id = ?`,
    ).bind(at(74), at(70), at(74), LEASE_ID),
    env.PG72_ID_DB.prepare(
      `INSERT INTO alert_evaluator_bootstrap
        (component, first_success_at, source_generation, source_revision)
       VALUES ('evaluator', ?, 999, 999)`,
    ).bind(at(74)),
  ])).rejects.toThrow();

  expect(await env.PG72_ID_DB.prepare(
    "SELECT status FROM alert_evaluator_run WHERE id = ?",
  ).bind(RUN_ID).first("status")).toBe("sealed");
  expect(await env.PG72_ID_DB.prepare(
    "SELECT lease_id FROM alert_runtime_status WHERE component = 'evaluator'",
  ).first("lease_id")).toBe(LEASE_ID);
  expect(await env.PG72_ID_DB.prepare(
    "SELECT count(*) AS count FROM alert_evaluator_bootstrap",
  ).first("count")).toBe(0);

  const results = await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `UPDATE alert_runtime_status
          SET status = 'healthy', revision = 2, lease_id = NULL,
              lease_expires_at = NULL, last_success_at = ?, watermark_at = ?,
              updated_at = ?
        WHERE component = 'evaluator' AND generation = 1
          AND revision = 1 AND lease_id = ?`,
    ).bind(at(74), at(70), at(74), LEASE_ID),
    env.PG72_ID_DB.prepare(
      `INSERT INTO alert_evaluator_bootstrap
        (component, first_success_at, source_generation, source_revision)
       SELECT component, last_success_at, generation, revision
         FROM alert_runtime_status
        WHERE component = 'evaluator' AND status = 'healthy'
          AND generation = 1 AND revision = 2
          AND last_success_at = ? AND watermark_at = ?
          AND NOT EXISTS (SELECT 1 FROM alert_evaluator_bootstrap)
          AND changes() = 1`,
    ).bind(at(74), at(70)),
  ]);
  expect(results[0]?.meta.changes).toBe(2);
  expect(results[1]?.meta.changes).toBe(1);
  expect(await env.PG72_ID_DB.prepare(
    `SELECT component, first_success_at, source_generation, source_revision
       FROM alert_evaluator_bootstrap`,
  ).first()).toEqual({
    component: "evaluator",
    first_success_at: at(74),
    source_generation: 1,
    source_revision: 2,
  });
  expect(await env.PG72_ID_DB.prepare(
    "SELECT status FROM alert_evaluator_run WHERE id = ?",
  ).bind(RUN_ID).first("status")).toBe("succeeded");
});
