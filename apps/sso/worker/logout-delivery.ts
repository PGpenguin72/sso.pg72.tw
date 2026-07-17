import { createAuth } from "./auth";
import { readRuntimeConfig } from "./config";
import {
  BACKCHANNEL_LOGOUT_EVENT,
  LOGOUT_DELIVERY_LEASE_SECONDS,
  LOGOUT_DELIVERY_MAX_ATTEMPTS,
  LOGOUT_TOKEN_LIFETIME_SECONDS,
  type LogoutDeliveryQueueMessage,
} from "./global-logout";

interface ClaimedLogoutDelivery {
  attempts: number;
  backchannel_logout_uri: string;
  client_id: string;
  delivery_key: string;
  id: number;
  jti: string;
  lease_id: string;
  replay_count: number;
  session_id: string;
}

interface DeliveryAttemptResult {
  errorCode: string | null;
  httpStatus: number | null;
  transient: boolean;
  delivered: boolean;
}

interface PersistedAttemptResult {
  delaySeconds?: number;
  status: "dead" | "delivered" | "retry";
}

const BACKOFF_SECONDS = [10, 30, 120, 300, 900] as const;

function addSeconds(iso: string, seconds: number): string {
  return new Date(new Date(iso).getTime() + seconds * 1000).toISOString();
}

async function recoverExpiredLogoutDelivery(
  env: Env,
  deliveryKey: string,
): Promise<void> {
  const now = new Date().toISOString();
  const expired = await env.PG72_ID_DB.prepare(
    `SELECT id, attempts, replay_count, lease_id
       FROM logout_delivery
      WHERE delivery_key = ?
        AND status = 'processing'
        AND lease_expires_at <= ?
      LIMIT 1`,
  )
    .bind(deliveryKey, now)
    .first<{
      attempts: number;
      id: number;
      lease_id: string;
      replay_count: number;
    }>();
  if (!expired) return;

  const resultingStatus = expired.attempts >= LOGOUT_DELIVERY_MAX_ATTEMPTS
    ? "dead"
    : "retry";
  const results = await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `UPDATE logout_delivery_attempt
          SET outcome = 'lease_expired',
              resulting_status = ?,
              error_code = 'lease_expired',
              completed_at = ?
        WHERE delivery_id = ?
          AND replay_count = ?
          AND attempt_number = ?
          AND lease_id = ?
          AND outcome = 'in_flight'`,
    ).bind(
      resultingStatus,
      now,
      expired.id,
      expired.replay_count,
      expired.attempts,
      expired.lease_id,
    ),
    env.PG72_ID_DB.prepare(
      `UPDATE logout_delivery
          SET status = ?,
              next_attempt_at = ?,
              lease_id = NULL,
              lease_expires_at = NULL,
              last_error_code = ?,
              updated_at = ?
        WHERE id = ?
          AND delivery_key = ?
          AND status = 'processing'
          AND attempts = ?
          AND replay_count = ?
          AND lease_id = ?
          AND lease_expires_at <= ?
          AND EXISTS (
            SELECT 1
              FROM logout_delivery_attempt
             WHERE delivery_id = ?
               AND replay_count = ?
               AND attempt_number = ?
               AND lease_id = ?
               AND outcome = 'lease_expired'
               AND resulting_status = ?
               AND completed_at = ?
          )`,
    ).bind(
      resultingStatus,
      resultingStatus === "retry" ? now : null,
      resultingStatus === "retry"
        ? "lease_expired"
        : "lease_expired_after_max_attempts",
      now,
      expired.id,
      deliveryKey,
      expired.attempts,
      expired.replay_count,
      expired.lease_id,
      now,
      expired.id,
      expired.replay_count,
      expired.attempts,
      expired.lease_id,
      resultingStatus,
      now,
    ),
  ]);
  if (results[0]?.meta.changes === 1 && results[1]?.meta.changes === 1) {
    return;
  }

  const stillExpired = await env.PG72_ID_DB.prepare(
    `SELECT 1
       FROM logout_delivery
      WHERE id = ?
        AND status = 'processing'
        AND lease_id = ?
        AND lease_expires_at <= ?
      LIMIT 1`,
  )
    .bind(expired.id, expired.lease_id, now)
    .first();
  if (stillExpired) {
    throw new Error("expired logout delivery attempt evidence was inconsistent");
  }
}

async function claimLogoutDelivery(
  env: Env,
  deliveryKey: string,
): Promise<ClaimedLogoutDelivery | null> {
  await recoverExpiredLogoutDelivery(env, deliveryKey);

  const now = new Date().toISOString();

  const leaseId = crypto.randomUUID();
  const jti = crypto.randomUUID();
  const attemptId = crypto.randomUUID();
  const leaseExpiresAt = addSeconds(now, LOGOUT_DELIVERY_LEASE_SECONDS);
  const claimed = await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `UPDATE logout_delivery
          SET status = 'processing',
              attempts = attempts + 1,
              jti = COALESCE(jti, ?),
              next_attempt_at = NULL,
              lease_id = ?,
              lease_expires_at = ?,
              updated_at = ?
        WHERE delivery_key = ?
          AND attempts < ?
          AND backchannel_logout_uri IS NOT NULL
          AND status IN ('pending', 'retry')
          AND next_attempt_at <= ?`,
    ).bind(
      jti,
      leaseId,
      leaseExpiresAt,
      now,
      deliveryKey,
      LOGOUT_DELIVERY_MAX_ATTEMPTS,
      now,
    ),
    env.PG72_ID_DB.prepare(
      `INSERT INTO logout_delivery_attempt
        (id, delivery_id, replay_count, attempt_number, lease_id, outcome,
         resulting_status, http_status, error_code, started_at, completed_at)
       SELECT ?, id, replay_count, attempts, ?, 'in_flight', 'processing',
              NULL, NULL, ?, NULL
         FROM logout_delivery
        WHERE delivery_key = ?
          AND status = 'processing'
          AND lease_id = ?
          AND updated_at = ?`,
    ).bind(attemptId, leaseId, now, deliveryKey, leaseId, now),
  ]);
  if (
    claimed[0]?.meta.changes !== 1 ||
    claimed[1]?.meta.changes !== 1
  ) {
    return null;
  }

  return env.PG72_ID_DB.prepare(
    `SELECT id, delivery_key, session_id, client_id,
            backchannel_logout_uri, attempts, replay_count, jti, lease_id
       FROM logout_delivery
      WHERE delivery_key = ? AND status = 'processing' AND lease_id = ?
      LIMIT 1`,
  )
    .bind(deliveryKey, leaseId)
    .first<ClaimedLogoutDelivery>();
}

async function createLogoutToken(
  env: Env,
  delivery: ClaimedLogoutDelivery,
): Promise<string> {
  const issuedAt = Math.floor(Date.now() / 1000);
  const config = readRuntimeConfig(env);
  const signed = await createAuth(env).api.signJWT({
    body: {
      payload: {
        iss: config.authBaseUrl,
        aud: delivery.client_id,
        iat: issuedAt,
        exp: issuedAt + LOGOUT_TOKEN_LIFETIME_SECONDS,
        jti: delivery.jti,
        events: { [BACKCHANNEL_LOGOUT_EVENT]: {} },
        sid: delivery.session_id,
      },
    },
  });
  return signed.token;
}

async function postLogoutToken(
  endpoint: string,
  logoutToken: string,
): Promise<DeliveryAttemptResult> {
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ logout_token: logoutToken }),
      redirect: "manual",
      signal: AbortSignal.timeout(8_000),
    });
    try {
      await response.body?.cancel();
    } catch {
      // Delivery classification depends only on the status code. Never read or
      // log an RP response body because it may contain application data.
    }

    if (response.status === 200 || response.status === 204) {
      return {
        delivered: true,
        errorCode: null,
        httpStatus: response.status,
        transient: false,
      };
    }
    if (
      response.status === 408 ||
      response.status === 425 ||
      response.status === 429 ||
      response.status >= 500
    ) {
      return {
        delivered: false,
        errorCode:
          response.status === 429
            ? "http_429"
            : response.status >= 500
              ? "http_5xx"
              : "http_retryable",
        httpStatus: response.status,
        transient: true,
      };
    }
    return {
      delivered: false,
      errorCode: "http_non_success",
      httpStatus: response.status,
      transient: false,
    };
  } catch (error) {
    return {
      delivered: false,
      errorCode:
        error instanceof Error && error.name === "TimeoutError"
          ? "timeout"
          : "network_error",
      httpStatus: null,
      transient: true,
    };
  }
}

async function persistAttemptResult(
  env: Env,
  delivery: ClaimedLogoutDelivery,
  result: DeliveryAttemptResult,
): Promise<PersistedAttemptResult> {
  const now = new Date().toISOString();
  const exhausted = delivery.attempts >= LOGOUT_DELIVERY_MAX_ATTEMPTS;
  const status: PersistedAttemptResult["status"] = result.delivered
    ? "delivered"
    : result.transient && !exhausted
      ? "retry"
      : "dead";
  const delaySeconds = status === "retry"
    ? BACKOFF_SECONDS[Math.min(delivery.attempts - 1, BACKOFF_SECONDS.length - 1)]
    : undefined;
  const nextAttemptAt = delaySeconds === undefined
    ? null
    : addSeconds(now, delaySeconds);
  const outcome = status === "delivered" ? "delivered" : status;
  const results = await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `UPDATE logout_delivery_attempt
          SET outcome = ?,
              resulting_status = ?,
              http_status = ?,
              error_code = ?,
              completed_at = ?
        WHERE delivery_id = ?
          AND replay_count = ?
          AND attempt_number = ?
          AND lease_id = ?
          AND outcome = 'in_flight'
          AND EXISTS (
            SELECT 1
              FROM logout_delivery
             WHERE id = ?
               AND status = 'processing'
               AND lease_id = ?
               AND attempts = ?
               AND replay_count = ?
          )`,
    ).bind(
      outcome,
      status,
      result.httpStatus,
      result.errorCode,
      now,
      delivery.id,
      delivery.replay_count,
      delivery.attempts,
      delivery.lease_id,
      delivery.id,
      delivery.lease_id,
      delivery.attempts,
      delivery.replay_count,
    ),
    env.PG72_ID_DB.prepare(
      `UPDATE logout_delivery
          SET status = ?,
              next_attempt_at = ?,
              lease_id = NULL,
              lease_expires_at = NULL,
              delivered_at = ?,
              last_error_code = ?,
              updated_at = ?
        WHERE id = ?
          AND status = 'processing'
          AND lease_id = ?
          AND attempts = ?
          AND replay_count = ?
          AND EXISTS (
            SELECT 1
              FROM logout_delivery_attempt
             WHERE delivery_id = ?
               AND replay_count = ?
               AND attempt_number = ?
               AND lease_id = ?
               AND outcome = ?
               AND resulting_status = ?
               AND completed_at = ?
          )`,
    ).bind(
      status,
      nextAttemptAt,
      status === "delivered" ? now : null,
      result.errorCode,
      now,
      delivery.id,
      delivery.lease_id,
      delivery.attempts,
      delivery.replay_count,
      delivery.id,
      delivery.replay_count,
      delivery.attempts,
      delivery.lease_id,
      outcome,
      status,
      now,
    ),
  ]);
  if (results[0]?.meta.changes !== 1 || results[1]?.meta.changes !== 1) {
    throw new Error("logout delivery lease changed before result commit");
  }
  return { status, ...(delaySeconds === undefined ? {} : { delaySeconds }) };
}

export async function consumeLogoutDeliveryMessage(
  message: Message<LogoutDeliveryQueueMessage>,
  env: Env,
): Promise<void> {
  let delivery: ClaimedLogoutDelivery | null;
  try {
    delivery = await claimLogoutDelivery(env, message.body.deliveryKey);
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "logout_delivery_claim_failed",
        deliveryKey: message.body.deliveryKey,
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
    message.retry({ delaySeconds: LOGOUT_DELIVERY_LEASE_SECONDS });
    return;
  }
  if (!delivery) {
    // A duplicate Queue delivery, a not-yet-due row, or a completed/dead row
    // needs no Queue retry. D1 remains authoritative and Cron replays due rows.
    message.ack();
    return;
  }

  let attempt: DeliveryAttemptResult;
  try {
    const token = await createLogoutToken(env, delivery);
    attempt = await postLogoutToken(
      delivery.backchannel_logout_uri,
      token,
    );
  } catch {
    attempt = {
      delivered: false,
      errorCode: "signing_error",
      httpStatus: null,
      transient: true,
    };
  }

  try {
    const persisted = await persistAttemptResult(env, delivery, attempt);
    if (persisted.status === "retry") {
      message.retry({ delaySeconds: persisted.delaySeconds });
    } else {
      message.ack();
    }
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "logout_delivery_result_failed",
        deliveryKey: delivery.delivery_key,
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
    message.retry({ delaySeconds: LOGOUT_DELIVERY_LEASE_SECONDS });
  }
}
