import { Hono } from "hono";

import { requireAdminPermission } from "./admin-gate";
import {
  createAuditEvent,
  enqueueSecurityEvent,
  type SecurityEvent,
} from "./audit";
import { enqueueDueLogoutDeliveries } from "./global-logout";

type AppEnv = { Bindings: Env };

const DELIVERY_ID_PATTERN = /^[1-9][0-9]{0,15}$/;
const DELIVERY_STATUSES = new Set([
  "dead",
  "delivered",
  "pending",
  "processing",
  "retry",
]);

interface DeliveryRow {
  attempts: number;
  client_id: string;
  created_at: string;
  id: number;
  last_error_code: string | null;
  reason: string;
  replay_count: number;
  status: string;
  updated_at: string;
}

interface ReplayRow {
  backchannel_logout_uri: string | null;
  client_id: string;
  current_backchannel_logout_uri: string | null;
  id: number;
  replay_count: number;
  status: string;
}

function replayAuditStatement(
  env: Env,
  event: SecurityEvent,
  deliveryId: number,
  replayCount: number,
  updatedAt: string,
): D1PreparedStatement {
  return env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, client_id, subject_id, outcome,
       metadata_json, occurred_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1
          FROM logout_delivery
         WHERE id = ?
           AND status = 'pending'
           AND replay_count = ?
           AND updated_at = ?
      )`,
  ).bind(
    event.eventId,
    event.eventType,
    event.actorUserId ?? null,
    event.clientId ?? null,
    event.subjectId ?? null,
    event.outcome,
    event.metadata ? JSON.stringify(event.metadata) : null,
    event.occurredAt,
    deliveryId,
    replayCount,
    updatedAt,
  );
}

export const adminLogoutDeliveryRoutes = new Hono<AppEnv>();

adminLogoutDeliveryRoutes.get("/", async (c) => {
  const gate = await requireAdminPermission(c, "users.manage");
  if (!gate.ok) return gate.response;

  const status = c.req.query("status") ?? "dead";
  if (!DELIVERY_STATUSES.has(status)) {
    return c.json({ error: "invalid_status" }, 400);
  }
  const rawLimit = c.req.query("limit") ?? "50";
  const limit = Number(rawLimit);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    return c.json({ error: "invalid_limit" }, 400);
  }

  const result = await c.env.PG72_ID_DB.prepare(
    `SELECT id, client_id, reason, status, attempts, replay_count,
            last_error_code, created_at, updated_at
       FROM logout_delivery
      WHERE status = ?
      ORDER BY updated_at DESC, id DESC
      LIMIT ?`,
  )
    .bind(status, limit)
    .all<DeliveryRow>();

  return c.json({
    deliveries: result.results.map((row) => ({
      id: row.id,
      clientId: row.client_id,
      reason: row.reason,
      status: row.status,
      attempts: row.attempts,
      replayCount: row.replay_count,
      lastErrorCode: row.last_error_code,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    })),
    status,
  });
});

adminLogoutDeliveryRoutes.post("/:deliveryId/replay", async (c) => {
  const gate = await requireAdminPermission(c, "users.manage", {
    fresh: true,
    passkeyStepUp: true,
  });
  if (!gate.ok) return gate.response;

  const deliveryIdRaw = c.req.param("deliveryId");
  if (!DELIVERY_ID_PATTERN.test(deliveryIdRaw)) {
    return c.json({ error: "invalid_delivery_id" }, 400);
  }
  const deliveryId = Number(deliveryIdRaw);
  if (!Number.isSafeInteger(deliveryId)) {
    return c.json({ error: "invalid_delivery_id" }, 400);
  }

  const row = await c.env.PG72_ID_DB.prepare(
    `SELECT delivery.id, delivery.client_id,
            delivery.backchannel_logout_uri, delivery.status,
            delivery.replay_count,
            client.backchannelLogoutUri AS current_backchannel_logout_uri
       FROM logout_delivery AS delivery
       LEFT JOIN oauthClient AS client
         ON client.clientId = delivery.client_id
      WHERE delivery.id = ?
      LIMIT 1`,
  )
    .bind(deliveryId)
    .first<ReplayRow>();
  if (!row) return c.json({ error: "delivery_not_found" }, 404);
  if (row.status !== "dead" && row.status !== "retry") {
    return c.json({ error: "delivery_not_replayable" }, 409);
  }
  const endpoint =
    row.backchannel_logout_uri ?? row.current_backchannel_logout_uri;
  if (!endpoint) {
    return c.json({ error: "backchannel_logout_uri_required" }, 409);
  }

  const now = new Date().toISOString();
  const replayCount = row.replay_count + 1;
  const event = createAuditEvent({
    eventType: "logout_delivery.replayed",
    outcome: "success",
    actorUserId: gate.actor.userId,
    clientId: row.client_id,
    metadata: { deliveryId, replayCount },
  });
  const results = await c.env.PG72_ID_DB.batch([
    c.env.PG72_ID_DB.prepare(
      `UPDATE logout_delivery
          SET backchannel_logout_uri = ?,
              status = 'pending',
              attempts = 0,
              replay_count = ?,
              next_attempt_at = ?,
              lease_id = NULL,
              lease_expires_at = NULL,
              delivered_at = NULL,
              last_error_code = NULL,
              updated_at = ?
        WHERE id = ?
          AND status IN ('dead', 'retry')
          AND replay_count = ?`,
    ).bind(
      endpoint,
      replayCount,
      now,
      now,
      deliveryId,
      row.replay_count,
    ),
    replayAuditStatement(c.env, event, deliveryId, replayCount, now),
  ]);
  if (results[0]?.meta.changes !== 1 || results[1]?.meta.changes !== 1) {
    return c.json({ error: "delivery_state_changed" }, 409);
  }

  await enqueueSecurityEvent(c.env, event, c.executionCtx);
  const dispatch = await enqueueDueLogoutDeliveries(c.env, { deliveryId });
  return c.json(
    {
      deliveryId,
      replayCount,
      queued: dispatch.queued === 1,
      status: "pending",
    },
    dispatch.queued === 1 ? 200 : 202,
  );
});
