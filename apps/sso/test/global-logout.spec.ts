import { env } from "cloudflare:workers";
import {
  createExecutionContext,
  waitOnExecutionContext,
} from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";

import { app } from "../worker/index";
import {
  enqueueDueLogoutDeliveries,
  revokeCentralSessions,
  type LogoutDeliveryQueueMessage,
} from "../worker/global-logout";
import { consumeLogoutDeliveryMessage } from "../worker/logout-delivery";
import {
  createAuthenticatedUser,
  createSessionFor,
  grantPasskeyStepUpForTest,
} from "./helpers";

interface QueueMessageState {
  acked: boolean;
  retries: Array<{ delaySeconds?: number }>;
}

interface DeliveryRow {
  attempts: number;
  client_id: string;
  id: number;
  jti: string | null;
  last_error_code: string | null;
  replay_count: number;
  status: string;
}

function fakeQueueEnv(
  send: (body: unknown) => Promise<void> = async () => {},
): Env {
  return {
    ...env,
    LOGOUT_DELIVERIES: { send: vi.fn(send) } as unknown as Queue,
    SECURITY_EVENTS: { send: vi.fn(async () => {}) } as unknown as Queue,
  } as Env;
}

function fakeMessage(deliveryId: number): {
  message: Message<LogoutDeliveryQueueMessage>;
  state: QueueMessageState;
} {
  const state: QueueMessageState = { acked: false, retries: [] };
  const message = {
    ack: () => {
      state.acked = true;
    },
    attempts: 1,
    body: { type: "logout_delivery", deliveryId } as const,
    id: crypto.randomUUID(),
    retry: (options?: { delaySeconds?: number }) => {
      state.retries.push(options ?? {});
    },
    timestamp: new Date(),
  } as Message<LogoutDeliveryQueueMessage>;
  return { message, state };
}

async function seedClient(
  backchannelLogoutUri: string | null = null,
): Promise<string> {
  const clientId = `logout-${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  const metadata = {
    developer_name: "Global Logout Test",
    ...(backchannelLogoutUri
      ? { backchannel_logout_uri: backchannelLogoutUri }
      : {}),
  };
  await env.PG72_ID_DB.prepare(
    `INSERT INTO oauthClient (
      id, clientId, disabled, skipConsent, enableEndSession, subjectType,
      scopes, createdAt, updatedAt, name, redirectUris,
      tokenEndpointAuthMethod, grantTypes, responseTypes, public, type,
      requirePKCE, metadata, backchannelLogoutUri
    ) VALUES (?, ?, 0, 0, 1, 'public', '["openid","offline_access"]',
              ?, ?, 'Global Logout Test', ?, 'none',
              '["authorization_code","refresh_token"]', '["code"]', 1,
              'web', 1, ?, ?)`,
  )
    .bind(
      crypto.randomUUID(),
      clientId,
      now,
      now,
      JSON.stringify([`https://${clientId}.example/callback`]),
      JSON.stringify(metadata),
      backchannelLogoutUri,
    )
    .run();
  return clientId;
}

async function seedIssuedTokens(
  userId: string,
  sessionId: string,
  clientId: string,
): Promise<void> {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString();
  const refreshId = crypto.randomUUID();
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `INSERT INTO oauthRefreshToken
        (id, token, clientId, sessionId, userId, expiresAt, createdAt, scopes)
       VALUES (?, ?, ?, ?, ?, ?, ?, '["openid","offline_access"]')`,
    ).bind(
      refreshId,
      crypto.randomUUID(),
      clientId,
      sessionId,
      userId,
      expiresAt,
      now.toISOString(),
    ),
    env.PG72_ID_DB.prepare(
      `INSERT INTO oauthAccessToken
        (id, token, clientId, sessionId, userId, refreshId, expiresAt,
         createdAt, scopes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, '["openid"]')`,
    ).bind(
      crypto.randomUUID(),
      crypto.randomUUID(),
      clientId,
      sessionId,
      userId,
      refreshId,
      expiresAt,
      now.toISOString(),
    ),
  ]);
}

async function revokeAll(
  testEnv: Env,
  user: Awaited<ReturnType<typeof createAuthenticatedUser>>,
) {
  return revokeCentralSessions(testEnv, {
    actorSessionId: user.sessionId,
    actorUserId: user.userId,
    eventType: "session.revoked_all",
    reason: "self_revoke",
    selector: { kind: "user_all", userId: user.userId },
    subjectUserId: user.userId,
  });
}

async function deliveryRow(id: number): Promise<DeliveryRow> {
  const row = await env.PG72_ID_DB.prepare(
    `SELECT id, client_id, status, attempts, replay_count, jti,
            last_error_code
       FROM logout_delivery
      WHERE id = ?`,
  )
    .bind(id)
    .first<DeliveryRow>();
  if (!row) throw new Error("logout delivery was not found");
  return row;
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const encoded = token.split(".")[1];
  if (!encoded) throw new Error("JWT payload was missing");
  const base64 = encoded
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(encoded.length / 4) * 4, "=");
  return JSON.parse(
    new TextDecoder().decode(
      Uint8Array.from(atob(base64), (value) => value.charCodeAt(0)),
    ),
  ) as Record<string, unknown>;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("durable global logout", () => {
  it("atomically records actual RP visits and snapshots every visited RP before revoke", async () => {
    const user = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const first = await seedClient(
      `https://first-${crypto.randomUUID()}.example/backchannel-logout`,
    );
    const second = await seedClient(
      `https://second-${crypto.randomUUID()}.example/backchannel-logout`,
    );
    await seedIssuedTokens(user.userId, user.sessionId, first);
    await seedIssuedTokens(user.userId, user.sessionId, second);

    const visits = await env.PG72_ID_DB.prepare(
      `SELECT client_id
         FROM rp_session_client
        WHERE session_id = ?
        ORDER BY client_id`,
    )
      .bind(user.sessionId)
      .all<{ client_id: string }>();
    expect(visits.results.map((row) => row.client_id)).toEqual(
      [first, second].sort(),
    );

    const queuedBodies: unknown[] = [];
    const revoked = await revokeAll(
      fakeQueueEnv(async (body) => {
        queuedBodies.push(body);
      }),
      user,
    );
    expect(revoked).toMatchObject({
      committed: true,
      logoutDeliveries: 2,
      revokedSessions: 1,
    });
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM session WHERE id = ?")
        .bind(user.sessionId)
        .first(),
    ).toBeNull();
    const remainingVisits = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM rp_session_client WHERE session_id = ?",
    )
      .bind(user.sessionId)
      .first<{ count: number }>();
    expect(remainingVisits?.count).toBe(0);
    const tokenState = await env.PG72_ID_DB.prepare(
      `SELECT
        (SELECT COUNT(*) FROM oauthAccessToken WHERE userId = ?) AS access_count,
        (SELECT COUNT(*) FROM oauthRefreshToken
          WHERE userId = ? AND revoked IS NOT NULL) AS revoked_refresh_count`,
    )
      .bind(user.userId, user.userId)
      .first<{ access_count: number; revoked_refresh_count: number }>();
    expect(tokenState).toEqual({ access_count: 0, revoked_refresh_count: 2 });

    const deliveries = await env.PG72_ID_DB.prepare(
      `SELECT client_id, status, backchannel_logout_uri
         FROM logout_delivery
        WHERE event_id = ?
        ORDER BY client_id`,
    )
      .bind(revoked.event.eventId)
      .all<{
        backchannel_logout_uri: string;
        client_id: string;
        status: string;
      }>();
    expect(deliveries.results).toHaveLength(2);
    expect(deliveries.results.every((row) => row.status === "pending")).toBe(
      true,
    );
    expect(
      queuedBodies.filter(
        (body) =>
          typeof body === "object" &&
          body !== null &&
          "type" in body &&
          body.type === "logout_delivery",
      ),
    ).toHaveLength(2);
  });

  it("rolls back audit, token revoke, and central logout when outbox persistence fails", async () => {
    const user = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const clientId = await seedClient(
      `https://rollback-${crypto.randomUUID()}.example/logout`,
    );
    await seedIssuedTokens(user.userId, user.sessionId, clientId);
    const auditBefore = await env.PG72_ID_DB.prepare(
      `SELECT COUNT(*) AS count
         FROM audit_event
        WHERE event_type = 'session.revoked_all' AND subject_id = ?`,
    )
      .bind(user.userId)
      .first<{ count: number }>();

    await env.PG72_ID_DB.prepare(
      `CREATE TRIGGER test_logout_outbox_abort
       BEFORE INSERT ON logout_delivery
       BEGIN
         SELECT RAISE(ABORT, 'synthetic outbox failure');
       END`,
    ).run();
    try {
      await expect(revokeAll(fakeQueueEnv(), user)).rejects.toThrow(
        "synthetic outbox failure",
      );
    } finally {
      await env.PG72_ID_DB.prepare(
        "DROP TRIGGER test_logout_outbox_abort",
      ).run();
    }

    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM session WHERE id = ?")
        .bind(user.sessionId)
        .first(),
    ).not.toBeNull();
    const tokens = await env.PG72_ID_DB.prepare(
      `SELECT
        (SELECT COUNT(*) FROM oauthAccessToken WHERE userId = ?) AS access_count,
        (SELECT COUNT(*) FROM oauthRefreshToken
          WHERE userId = ? AND revoked IS NULL) AS live_refresh_count`,
    )
      .bind(user.userId, user.userId)
      .first<{ access_count: number; live_refresh_count: number }>();
    expect(tokens).toEqual({ access_count: 1, live_refresh_count: 1 });
    const auditAfter = await env.PG72_ID_DB.prepare(
      `SELECT COUNT(*) AS count
         FROM audit_event
        WHERE event_type = 'session.revoked_all' AND subject_id = ?`,
    )
      .bind(user.userId)
      .first<{ count: number }>();
    expect(auditAfter?.count).toBe(auditBefore?.count);
  });

  it("uses the atomic path for self-service single-session revoke", async () => {
    const user = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const target = await createSessionFor(user.userId);
    const clientId = await seedClient(
      `https://self-revoke-${crypto.randomUUID()}.example/logout`,
    );
    await seedIssuedTokens(user.userId, target.sessionId, clientId);
    const context = createExecutionContext();
    const response = await app.fetch(
      new Request("http://localhost:5173/revoke-session", {
        method: "POST",
        headers: user.headers,
        body: JSON.stringify({ token: target.token }),
      }),
      fakeQueueEnv(),
      context,
    );
    await waitOnExecutionContext(context);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: true });
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM session WHERE id = ?")
        .bind(user.sessionId)
        .first(),
    ).not.toBeNull();
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM session WHERE id = ?")
        .bind(target.sessionId)
        .first(),
    ).toBeNull();
    const outbox = await env.PG72_ID_DB.prepare(
      `SELECT reason, status
         FROM logout_delivery
        WHERE session_id = ? AND client_id = ?
        LIMIT 1`,
    )
      .bind(target.sessionId, clientId)
      .first<{ reason: string; status: string }>();
    expect(outbox).toEqual({ reason: "self_revoke", status: "pending" });
  });

  it("atomically snapshots logout work for suspend, restrict, and admin revoke", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const cases = [
      {
        body: JSON.stringify({ suspended: true }),
        path: "status",
        reason: "suspend",
      },
      {
        body: JSON.stringify({ restricted: true }),
        path: "access",
        reason: "restrict",
      },
      { body: undefined, path: "revoke-sessions", reason: "admin_revoke" },
    ] as const;

    for (const testCase of cases) {
      const target = await createAuthenticatedUser(
        `${crypto.randomUUID()}@example.com`,
      );
      const clientId = await seedClient(
        `https://${testCase.reason}-${crypto.randomUUID()}.example/logout`,
      );
      await seedIssuedTokens(target.userId, target.sessionId, clientId);
      const context = createExecutionContext();
      const response = await app.fetch(
        new Request(
          `http://localhost:5173/api/admin/users/${target.userId}/${testCase.path}`,
          {
            method: "POST",
            headers: admin.headers,
            ...(testCase.body === undefined ? {} : { body: testCase.body }),
          },
        ),
        fakeQueueEnv(),
        context,
      );
      await waitOnExecutionContext(context);
      expect(response.status, testCase.reason).toBe(200);
      expect(
        await env.PG72_ID_DB.prepare("SELECT id FROM session WHERE id = ?")
          .bind(target.sessionId)
          .first(),
      ).toBeNull();
      const source = await env.PG72_ID_DB.prepare(
        `SELECT
          (SELECT COUNT(*) FROM oauthAccessToken WHERE userId = ?) AS access_count,
          (SELECT COUNT(*) FROM oauthRefreshToken
            WHERE userId = ? AND revoked IS NOT NULL) AS revoked_refresh_count`,
      )
        .bind(target.userId, target.userId)
        .first<{ access_count: number; revoked_refresh_count: number }>();
      expect(source).toEqual({ access_count: 0, revoked_refresh_count: 1 });
      const delivery = await env.PG72_ID_DB.prepare(
        `SELECT reason, status
           FROM logout_delivery
          WHERE session_id = ? AND client_id = ?
          LIMIT 1`,
      )
        .bind(target.sessionId, clientId)
        .first<{ reason: string; status: string }>();
      expect(delivery).toEqual({
        reason: testCase.reason,
        status: "pending",
      });
    }
  });

  it("signs the required claims, delivers once, and acknowledges Queue duplicates", async () => {
    const user = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const endpoint = `https://receiver-${crypto.randomUUID()}.example/logout`;
    const clientId = await seedClient(endpoint);
    await seedIssuedTokens(user.userId, user.sessionId, clientId);
    const revoked = await revokeAll(fakeQueueEnv(), user);
    const row = await env.PG72_ID_DB.prepare(
      "SELECT id FROM logout_delivery WHERE event_id = ? LIMIT 1",
    )
      .bind(revoked.event.eventId)
      .first<{ id: number }>();
    if (!row) throw new Error("delivery was not created");

    let postedToken = "";
    const outbound = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      expect(request.url).toBe(endpoint);
      expect(request.redirect).toBe("manual");
      const form = await request.formData();
      postedToken = String(form.get("logout_token") ?? "");
      return new Response(null, { status: 204 });
    });
    vi.stubGlobal("fetch", outbound);

    const first = fakeMessage(row.id);
    await consumeLogoutDeliveryMessage(first.message, fakeQueueEnv());
    expect(first.state).toEqual({ acked: true, retries: [] });
    const delivered = await deliveryRow(row.id);
    expect(delivered).toMatchObject({ attempts: 1, status: "delivered" });
    const payload = decodeJwtPayload(postedToken);
    expect(payload).toMatchObject({
      aud: clientId,
      events: {
        "http://schemas.openid.net/event/backchannel-logout": {},
      },
      iss: "http://localhost:5173",
      jti: delivered.jti,
      sid: user.sessionId,
    });
    expect(payload).not.toHaveProperty("nonce");
    expect((payload.exp as number) - (payload.iat as number)).toBe(120);

    const duplicate = fakeMessage(row.id);
    await consumeLogoutDeliveryMessage(duplicate.message, fakeQueueEnv());
    expect(duplicate.state).toEqual({ acked: true, retries: [] });
    expect(outbound).toHaveBeenCalledTimes(1);
    expect(await deliveryRow(row.id)).toMatchObject({
      attempts: 1,
      status: "delivered",
    });
  });

  it("retries timeout and 5xx outcomes with bounded backoff, then exposes dead evidence", async () => {
    const user = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const clientId = await seedClient(
      `https://failure-${crypto.randomUUID()}.example/logout`,
    );
    await seedIssuedTokens(user.userId, user.sessionId, clientId);
    const revoked = await revokeAll(fakeQueueEnv(), user);
    const delivery = await env.PG72_ID_DB.prepare(
      "SELECT id FROM logout_delivery WHERE event_id = ? LIMIT 1",
    )
      .bind(revoked.event.eventId)
      .first<{ id: number }>();
    if (!delivery) throw new Error("delivery was not created");

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new DOMException("timed out", "TimeoutError");
      }),
    );
    const timedOut = fakeMessage(delivery.id);
    await consumeLogoutDeliveryMessage(timedOut.message, fakeQueueEnv());
    expect(timedOut.state.retries[0]?.delaySeconds).toBe(10);
    expect(await deliveryRow(delivery.id)).toMatchObject({
      attempts: 1,
      last_error_code: "timeout",
      status: "retry",
    });

    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 503 })));
    for (let attempt = 2; attempt <= 5; attempt += 1) {
      await env.PG72_ID_DB.prepare(
        "UPDATE logout_delivery SET next_attempt_at = ? WHERE id = ?",
      )
        .bind(new Date(0).toISOString(), delivery.id)
        .run();
      const message = fakeMessage(delivery.id);
      await consumeLogoutDeliveryMessage(message.message, fakeQueueEnv());
      if (attempt < 5) {
        expect(message.state.acked).toBe(false);
        expect(message.state.retries).toHaveLength(1);
      } else {
        expect(message.state).toEqual({ acked: true, retries: [] });
      }
    }
    expect(await deliveryRow(delivery.id)).toMatchObject({
      attempts: 5,
      last_error_code: "http_5xx",
      status: "dead",
    });
    const attempts = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM logout_delivery_attempt WHERE delivery_id = ?",
    )
      .bind(delivery.id)
      .first<{ count: number }>();
    expect(attempts?.count).toBe(5);
  });

  it("keeps partial Queue failures durable and replays an expired lease", async () => {
    const user = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const first = await seedClient(
      `https://partial-a-${crypto.randomUUID()}.example/logout`,
    );
    const second = await seedClient(
      `https://partial-b-${crypto.randomUUID()}.example/logout`,
    );
    await seedIssuedTokens(user.userId, user.sessionId, first);
    await seedIssuedTokens(user.userId, user.sessionId, second);
    const revoked = await revokeAll(fakeQueueEnv(), user);
    const rows = await env.PG72_ID_DB.prepare(
      "SELECT id FROM logout_delivery WHERE event_id = ? ORDER BY id",
    )
      .bind(revoked.event.eventId)
      .all<{ id: number }>();
    expect(rows.results).toHaveLength(2);
    await env.PG72_ID_DB.prepare(
      `UPDATE logout_delivery
          SET status = 'dead', next_attempt_at = NULL,
              last_error_code = 'test_isolation'
        WHERE event_id <> ? AND status IN ('pending', 'retry')`,
    )
      .bind(revoked.event.eventId)
      .run();

    const failedId = rows.results[1]?.id;
    const dispatched = await enqueueDueLogoutDeliveries(
      fakeQueueEnv(async (body) => {
        if (
          typeof body === "object" &&
          body !== null &&
          "deliveryId" in body &&
          body.deliveryId === failedId
        ) {
          throw new Error("synthetic queue failure");
        }
      }),
    );
    expect(dispatched).toMatchObject({ attempted: 2, failed: 1, queued: 1 });
    for (const row of rows.results) {
      expect(await deliveryRow(row.id)).toMatchObject({ status: "pending" });
    }

    const expiredId = rows.results[0]?.id;
    if (!expiredId) throw new Error("expired delivery was missing");
    await env.PG72_ID_DB.prepare(
      `UPDATE logout_delivery
          SET status = 'processing', attempts = 1, jti = ?, lease_id = ?,
              next_attempt_at = NULL, lease_expires_at = ?
        WHERE id = ?`,
    )
      .bind(
        crypto.randomUUID(),
        crypto.randomUUID(),
        new Date(0).toISOString(),
        expiredId,
      )
      .run();
    const replayed: unknown[] = [];
    const replay = await enqueueDueLogoutDeliveries(
      fakeQueueEnv(async (body) => {
        replayed.push(body);
      }),
      { deliveryId: expiredId },
    );
    expect(replay).toEqual({ attempted: 1, failed: 0, queued: 1 });
    expect(replayed).toEqual([
      { type: "logout_delivery", deliveryId: expiredId },
    ]);
  });

  it("serializes concurrent revoke and lets an operator replay dead delivery state", async () => {
    const user = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const endpoint = `https://replay-${crypto.randomUUID()}.example/logout`;
    const clientId = await seedClient(endpoint);
    await seedIssuedTokens(user.userId, user.sessionId, clientId);
    const testEnv = fakeQueueEnv();
    const concurrent = await Promise.all([
      revokeAll(testEnv, user),
      revokeAll(testEnv, user),
    ]);
    expect(concurrent.filter((result) => result.committed)).toHaveLength(1);
    const committed = concurrent.find((result) => result.committed);
    if (!committed) throw new Error("concurrent revoke did not commit");
    const delivery = await env.PG72_ID_DB.prepare(
      "SELECT id FROM logout_delivery WHERE event_id = ? LIMIT 1",
    )
      .bind(committed.event.eventId)
      .first<{ id: number }>();
    if (!delivery) throw new Error("delivery was not created");
    await env.PG72_ID_DB.prepare(
      `UPDATE logout_delivery
          SET status = 'dead', attempts = 5, next_attempt_at = NULL,
              last_error_code = 'http_5xx'
        WHERE id = ?`,
    )
      .bind(delivery.id)
      .run();

    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    await grantPasskeyStepUpForTest(admin.userId, admin.sessionId);
    const replayContext = createExecutionContext();
    const response = await app.fetch(
      new Request(
        `http://localhost:5173/api/admin/logout-deliveries/${delivery.id}/replay`,
        { method: "POST", headers: admin.headers },
      ),
      fakeQueueEnv(),
      replayContext,
    );
    await waitOnExecutionContext(replayContext);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      deliveryId: delivery.id,
      queued: true,
      replayCount: 1,
      status: "pending",
    });
    expect(await deliveryRow(delivery.id)).toMatchObject({
      attempts: 0,
      last_error_code: null,
      replay_count: 1,
      status: "pending",
    });

    const listingContext = createExecutionContext();
    const listing = await app.fetch(
      new Request(
        "http://localhost:5173/api/admin/logout-deliveries?status=pending",
        { headers: admin.headers },
      ),
      fakeQueueEnv(),
      listingContext,
    );
    await waitOnExecutionContext(listingContext);
    expect(listing.status).toBe(200);
    const listed = (await listing.json()) as {
      deliveries: Array<Record<string, unknown>>;
    };
    const listedDelivery = listed.deliveries.find(
      (item) => item.id === delivery.id,
    );
    expect(listedDelivery).toMatchObject({
      clientId,
      lastErrorCode: null,
      replayCount: 1,
      status: "pending",
    });
    expect(listedDelivery).not.toHaveProperty("backchannelLogoutUri");
    expect(listedDelivery).not.toHaveProperty("jti");
    expect(listedDelivery).not.toHaveProperty("sessionId");
  });
});
