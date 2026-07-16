import {
  createAuditEvent,
  enqueueSecurityEvent,
  type SecurityEvent,
  type WaitUntilContext,
} from "./audit";

export const BACKCHANNEL_LOGOUT_EVENT =
  "http://schemas.openid.net/event/backchannel-logout";
export const LOGOUT_DELIVERY_MAX_ATTEMPTS = 5;
export const LOGOUT_DELIVERY_LEASE_SECONDS = 30;
export const LOGOUT_TOKEN_LIFETIME_SECONDS = 120;

export type LogoutReason =
  | "account_delete"
  | "admin_revoke"
  | "restrict"
  | "rp_initiated_logout"
  | "self_revoke"
  | "sign_out"
  | "suspend";

export interface LogoutDeliveryQueueMessage {
  type: "logout_delivery";
  deliveryId: number;
}

export interface LogoutDispatchResult {
  attempted: number;
  failed: number;
  queued: number;
}

export interface RevocationResult {
  committed: boolean;
  event: SecurityEvent;
  logoutDeliveries: number;
  revokedSessions: number;
}

type SessionSelector =
  | { kind: "session"; sessionId: string; userId: string; token?: string }
  | { kind: "user_all"; userId: string }
  | { kind: "user_others"; exceptSessionId: string; userId: string };

interface CentralSessionRevocationInput {
  actorSessionId?: string;
  actorUserId?: string;
  clientId?: string;
  eventType: string;
  freshAfter?: string;
  reason: LogoutReason;
  selector: SessionSelector;
  subjectUserId: string;
}

interface SelectorSql {
  bindings: unknown[];
  sql: string;
}

function selectorSql(selector: SessionSelector, alias: string): SelectorSql {
  if (selector.kind === "user_all") {
    return { sql: `${alias}.userId = ?`, bindings: [selector.userId] };
  }
  if (selector.kind === "user_others") {
    return {
      sql: `${alias}.userId = ? AND ${alias}.id <> ?`,
      bindings: [selector.userId, selector.exceptSessionId],
    };
  }
  return {
    sql: `${alias}.id = ? AND ${alias}.userId = ?${
      selector.token === undefined ? "" : ` AND ${alias}.token = ?`
    }`,
    bindings:
      selector.token === undefined
        ? [selector.sessionId, selector.userId]
        : [selector.sessionId, selector.userId, selector.token],
  };
}

function auditForRevocationStatement(
  env: Env,
  event: SecurityEvent,
  input: CentralSessionRevocationInput,
  now: string,
): D1PreparedStatement {
  let eligibility: string;
  let eligibilityBindings: unknown[];
  if (input.actorSessionId && input.actorUserId) {
    eligibility = `EXISTS (
      SELECT 1
        FROM session AS actor_session
       WHERE actor_session.id = ?
         AND actor_session.userId = ?
         AND actor_session.expiresAt > ?
         ${input.freshAfter ? "AND actor_session.createdAt > ?" : ""}
    )`;
    eligibilityBindings = [
      input.actorSessionId,
      input.actorUserId,
      now,
      ...(input.freshAfter ? [input.freshAfter] : []),
    ];
  } else {
    const selector = selectorSql(input.selector, "target_session");
    eligibility = `EXISTS (
      SELECT 1
        FROM session AS target_session
       WHERE ${selector.sql}
    )`;
    eligibilityBindings = selector.bindings;
  }

  return env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, client_id, subject_id, outcome,
       metadata_json, occurred_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?
      WHERE ${eligibility}`,
  ).bind(
    event.eventId,
    event.eventType,
    event.actorUserId ?? null,
    event.clientId ?? null,
    event.subjectId ?? null,
    event.outcome,
    event.metadata ? JSON.stringify(event.metadata) : null,
    event.occurredAt,
    ...eligibilityBindings,
  );
}

function logoutOutboxStatement(
  env: Env,
  eventId: string,
  selector: SessionSelector,
  reason: LogoutReason,
  now: string,
): D1PreparedStatement {
  const selected = selectorSql(selector, "central_session");
  return env.PG72_ID_DB.prepare(
    `INSERT INTO logout_delivery (
       event_id, session_id, user_id, client_id, backchannel_logout_uri,
       reason, status, attempts, replay_count, next_attempt_at,
       last_error_code, created_at, updated_at
     )
     SELECT ?, visit.session_id, central_session.userId, visit.client_id,
            client.backchannelLogoutUri, ?,
            CASE
              WHEN client.backchannelLogoutUri IS NULL THEN 'dead'
              ELSE 'pending'
            END,
            0, 0,
            CASE
              WHEN client.backchannelLogoutUri IS NULL THEN NULL
              ELSE ?
            END,
            CASE
              WHEN client.backchannelLogoutUri IS NULL
                THEN 'missing_backchannel_uri'
              ELSE NULL
            END,
            ?, ?
       FROM rp_session_client AS visit
       JOIN session AS central_session
         ON central_session.id = visit.session_id
       JOIN oauthClient AS client
         ON client.clientId = visit.client_id
      WHERE ${selected.sql}
        AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)
     ON CONFLICT (event_id, session_id, client_id) DO NOTHING`,
  ).bind(
    eventId,
    reason,
    now,
    now,
    now,
    ...selected.bindings,
    eventId,
  );
}

function refreshRevocationStatement(
  env: Env,
  eventId: string,
  selector: SessionSelector,
  now: string,
): D1PreparedStatement {
  const selected = selectorSql(selector, "selected_session");
  return env.PG72_ID_DB.prepare(
    `UPDATE oauthRefreshToken
        SET revoked = ?
      WHERE revoked IS NULL
        AND sessionId IN (
          SELECT selected_session.id
            FROM session AS selected_session
           WHERE ${selected.sql}
        )
        AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
  ).bind(now, ...selected.bindings, eventId);
}

function accessTokenRevocationStatement(
  env: Env,
  eventId: string,
  selector: SessionSelector,
): D1PreparedStatement {
  const selected = selectorSql(selector, "selected_session");
  return env.PG72_ID_DB.prepare(
    `DELETE FROM oauthAccessToken
      WHERE sessionId IN (
        SELECT selected_session.id
          FROM session AS selected_session
         WHERE ${selected.sql}
      )
        AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
  ).bind(...selected.bindings, eventId);
}

function sessionRevocationStatement(
  env: Env,
  eventId: string,
  selector: SessionSelector,
): D1PreparedStatement {
  const selected = selectorSql(selector, "session");
  return env.PG72_ID_DB.prepare(
    `DELETE FROM session
      WHERE ${selected.sql}
        AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)
      RETURNING id`,
  ).bind(...selected.bindings, eventId);
}

/**
 * Statements appended to an existing guarded admin transaction. The caller
 * must insert the matching audit_event first and delete central sessions only
 * after these statements, which keeps the endpoint snapshot and token revoke
 * in the same D1 transaction as the account transition.
 */
export function globalLogoutForUserStatements(
  env: Env,
  input: {
    eventId: string;
    now: string;
    reason: LogoutReason;
    userId: string;
  },
): D1PreparedStatement[] {
  const selector: SessionSelector = { kind: "user_all", userId: input.userId };
  return [
    logoutOutboxStatement(env, input.eventId, selector, input.reason, input.now),
    env.PG72_ID_DB.prepare(
      `UPDATE oauthRefreshToken
          SET revoked = ?
        WHERE userId = ?
          AND revoked IS NULL
          AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
    ).bind(input.now, input.userId, input.eventId),
    env.PG72_ID_DB.prepare(
      `DELETE FROM oauthAccessToken
        WHERE userId = ?
          AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
    ).bind(input.userId, input.eventId),
  ];
}

export async function revokeCentralSessions(
  env: Env,
  input: CentralSessionRevocationInput,
  executionCtx?: WaitUntilContext,
): Promise<RevocationResult> {
  const now = new Date().toISOString();
  const event = createAuditEvent({
    eventType: input.eventType,
    outcome: "success",
    actorUserId: input.actorUserId,
    clientId: input.clientId,
    subjectId: input.subjectUserId,
    metadata: { reason: input.reason },
  });
  const results = await env.PG72_ID_DB.batch([
    auditForRevocationStatement(env, event, input, now),
    logoutOutboxStatement(env, event.eventId, input.selector, input.reason, now),
    refreshRevocationStatement(env, event.eventId, input.selector, now),
    accessTokenRevocationStatement(env, event.eventId, input.selector),
    sessionRevocationStatement(env, event.eventId, input.selector),
  ]);
  const committed = results[0]?.meta.changes === 1;
  if (committed) {
    await enqueueSecurityEvent(env, event, executionCtx);
    await scheduleLogoutDeliveryDispatch(env, executionCtx);
  }
  return {
    committed,
    event,
    logoutDeliveries: results[1]?.meta.changes ?? 0,
    revokedSessions: results[4]?.results.length ?? 0,
  };
}

export async function enqueueDueLogoutDeliveries(
  env: Env,
  options: { deliveryId?: number; limit?: number } = {},
): Promise<LogoutDispatchResult> {
  const now = new Date().toISOString();
  const limit = Math.min(Math.max(options.limit ?? 50, 1), 100);
  await env.PG72_ID_DB.prepare(
    `UPDATE logout_delivery
        SET status = 'dead',
            lease_expires_at = NULL,
            last_error_code = 'lease_expired_after_max_attempts',
            updated_at = ?
      WHERE status = 'processing'
        AND attempts >= ?
        AND lease_expires_at <= ?`,
  )
    .bind(now, LOGOUT_DELIVERY_MAX_ATTEMPTS, now)
    .run();
  const due = options.deliveryId === undefined
    ? await env.PG72_ID_DB.prepare(
        `SELECT id
           FROM logout_delivery
          WHERE (
              status IN ('pending', 'retry')
              AND next_attempt_at <= ?
            )
             OR (
              status = 'processing'
              AND lease_expires_at <= ?
            )
          ORDER BY created_at ASC, id ASC
          LIMIT ?`,
      ).bind(now, now, limit).all<{ id: number }>()
    : await env.PG72_ID_DB.prepare(
        `SELECT id
           FROM logout_delivery
          WHERE id = ?
            AND (
              (status IN ('pending', 'retry') AND next_attempt_at <= ?)
              OR (status = 'processing' AND lease_expires_at <= ?)
            )
          LIMIT 1`,
      ).bind(options.deliveryId, now, now).all<{ id: number }>();

  const sends = await Promise.allSettled(
    due.results.map((row) =>
      env.LOGOUT_DELIVERIES.send({
        type: "logout_delivery",
        deliveryId: row.id,
      } satisfies LogoutDeliveryQueueMessage),
    ),
  );
  let failed = 0;
  sends.forEach((result, index) => {
    if (result.status === "fulfilled") return;
    failed += 1;
    console.error(
      JSON.stringify({
        event: "logout_delivery_enqueue_failed",
        deliveryId: due.results[index]?.id,
        error:
          result.reason instanceof Error ? result.reason.name : "UnknownError",
      }),
    );
  });
  return {
    attempted: sends.length,
    failed,
    queued: sends.length - failed,
  };
}

export async function scheduleLogoutDeliveryDispatch(
  env: Env,
  executionCtx?: WaitUntilContext,
): Promise<void> {
  const queued = enqueueDueLogoutDeliveries(env).catch((error: unknown) => {
    console.error(
      JSON.stringify({
        event: "logout_outbox_dispatch_failed",
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
  });
  if (!executionCtx) {
    await queued;
    return;
  }
  try {
    executionCtx.waitUntil(queued);
  } catch {
    await queued;
  }
}

export function isLogoutDeliveryQueueMessage(
  value: unknown,
): value is LogoutDeliveryQueueMessage {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<LogoutDeliveryQueueMessage>;
  return (
    candidate.type === "logout_delivery" &&
    typeof candidate.deliveryId === "number" &&
    Number.isSafeInteger(candidate.deliveryId) &&
    candidate.deliveryId > 0
  );
}
