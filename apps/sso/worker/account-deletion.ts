import { getSessionCookie } from "better-auth/cookies";
import { constantTimeEqual, makeSignature } from "better-auth/crypto";

import {
  createAuditEvent,
  type SecurityEvent,
} from "./audit";
import { ownedClientShutdownStatements } from "./client-ownership";
import { globalLogoutForUserStatements } from "./global-logout";

interface AccountDeleteSnapshot {
  accessLevel: string;
  email: string;
  emailVerified: number;
  role: string | null;
  sessionCreatedAt: string;
  sessionExpiresAt: string;
  sessionId: string;
  sessionToken: string;
  sessionUpdatedAt: string;
  status: string;
  userUpdatedAt: string;
  userId: string;
}

export interface AtomicAccountDeleteResult {
  committed: boolean;
  event: SecurityEvent;
  logoutDeliveries: number;
}

async function verifiedSessionToken(
  request: Request,
  secret: string,
): Promise<string | null> {
  const signed = getSessionCookie(request, { cookiePrefix: "pg72_id" });
  if (!signed) return null;
  const separator = signed.lastIndexOf(".");
  if (separator <= 0 || separator === signed.length - 1) return null;

  const token = signed.slice(0, separator);
  const signature = signed.slice(separator + 1);
  const expected = await makeSignature(token, secret);
  return constantTimeEqual(signature, expected) ? token : null;
}

async function loadAccountDeleteSnapshot(
  env: Env,
  request: Request,
  userId: string,
): Promise<AccountDeleteSnapshot | null> {
  const sessionToken = await verifiedSessionToken(
    request,
    env.BETTER_AUTH_SECRET,
  );
  if (!sessionToken) return null;
  const now = new Date().toISOString();
  return env.PG72_ID_DB.prepare(
    `SELECT session.id AS sessionId, session.token AS sessionToken,
            session.createdAt AS sessionCreatedAt,
            session.updatedAt AS sessionUpdatedAt,
            session.expiresAt AS sessionExpiresAt,
            user.id AS userId, user.email, user.emailVerified, user.role,
            user.status, user.accessLevel, user.updatedAt AS userUpdatedAt
       FROM session
       JOIN user ON user.id = session.userId
      WHERE session.token = ?
        AND session.userId = ?
        AND session.expiresAt > ?
      LIMIT 1`,
  )
    .bind(sessionToken, userId, now)
    .first<AccountDeleteSnapshot>();
}

function successAuditStatement(
  env: Env,
  event: SecurityEvent,
  snapshot: AccountDeleteSnapshot,
  now: string,
): D1PreparedStatement {
  return env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, client_id, subject_id, outcome,
       metadata_json, occurred_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1
          FROM session
         WHERE id = ?
           AND token = ?
           AND userId = ?
           AND createdAt = ?
           AND updatedAt = ?
           AND expiresAt = ?
           AND expiresAt > ?
      )
        AND EXISTS (
          SELECT 1
            FROM user
           WHERE id = ?
             AND email = ?
             AND emailVerified = ?
             AND role IS ?
             AND status = ?
             AND accessLevel = ?
             AND updatedAt = ?
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
    snapshot.sessionId,
    snapshot.sessionToken,
    snapshot.userId,
    snapshot.sessionCreatedAt,
    snapshot.sessionUpdatedAt,
    snapshot.sessionExpiresAt,
    now,
    snapshot.userId,
    snapshot.email,
    snapshot.emailVerified,
    snapshot.role,
    snapshot.status,
    snapshot.accessLevel,
    snapshot.userUpdatedAt,
  );
}

export async function deleteOwnAccountAtomically(
  env: Env,
  input: { request: Request; userId: string },
): Promise<AtomicAccountDeleteResult> {
  const snapshot = await loadAccountDeleteSnapshot(
    env,
    input.request,
    input.userId,
  );
  const event = createAuditEvent({
    eventType: "account.deleted",
    outcome: "success",
    actorUserId: input.userId,
    subjectId: input.userId,
  });
  if (!snapshot) {
    return { committed: false, event, logoutDeliveries: 0 };
  }

  const now = new Date().toISOString();
  const globalLogout = globalLogoutForUserStatements(env, {
    eventId: event.eventId,
    now,
    reason: "account_delete",
    userId: snapshot.userId,
  });
  const ownedClientShutdown = ownedClientShutdownStatements(
    env,
    snapshot.userId,
    now,
    event.eventId,
  );
  const results = await env.PG72_ID_DB.batch([
    successAuditStatement(env, event, snapshot, now),
    ...globalLogout,
    ...ownedClientShutdown,
    env.PG72_ID_DB.prepare(
      `DELETE FROM session
        WHERE userId = ?
          AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
    ).bind(snapshot.userId, event.eventId),
    env.PG72_ID_DB.prepare(
      `DELETE FROM account
        WHERE userId = ?
          AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
    ).bind(snapshot.userId, event.eventId),
    env.PG72_ID_DB.prepare(
      `DELETE FROM user
        WHERE id = ?
          AND email = ?
          AND emailVerified = ?
          AND role IS ?
          AND status = ?
          AND accessLevel = ?
          AND updatedAt = ?
          AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)
        RETURNING id`,
    ).bind(
      snapshot.userId,
      snapshot.email,
      snapshot.emailVerified,
      snapshot.role,
      snapshot.status,
      snapshot.accessLevel,
      snapshot.userUpdatedAt,
      event.eventId,
    ),
  ]);

  const committed =
    results[0]?.meta.changes === 1 &&
    results[results.length - 1]?.results.length === 1;
  return {
    committed,
    event,
    logoutDeliveries: results[1]?.meta.changes ?? 0,
  };
}
