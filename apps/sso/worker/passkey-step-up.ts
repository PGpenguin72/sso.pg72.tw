import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
} from "@simplewebauthn/server";
import { Hono } from "hono";

import {
  createAuditEvent,
  enqueueSecurityEvent,
  recordAudit,
  type SecurityEvent,
  type WaitUntilContext,
} from "./audit";
import { createAuth } from "./auth";
import {
  FRESH_SESSION_MAX_AGE_MS,
  PASSKEY_STEP_UP_CHALLENGE_TTL_MS,
  readRuntimeConfig,
} from "./config";

type AppEnv = { Bindings: Env };

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const ASSERTION_FIELD_MAX_LENGTH = 8 * 1024;

interface PasskeySummaryRow {
  credentialID: string;
}

interface PasskeyVerificationRow {
  counter: number;
  credentialID: string;
  id: string;
  publicKey: string;
}

interface StepUpChallengeRow {
  challenge: string;
}

interface StepUpSessionRow {
  has_passkey: number;
  verified_at: string | null;
}

export interface PasskeyStepUpState {
  expiresAt: string | null;
  hasPasskey: boolean;
  verified: boolean;
  verifiedAt: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validBase64Url(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= ASSERTION_FIELD_MAX_LENGTH &&
    BASE64URL_PATTERN.test(value)
  );
}

function parseAuthenticationResponse(
  value: unknown,
): AuthenticationResponseJSON | null {
  if (!isRecord(value) || !isRecord(value.response)) return null;
  const response = value.response;
  if (
    value.type !== "public-key" ||
    !validBase64Url(value.id) ||
    !validBase64Url(value.rawId) ||
    value.id !== value.rawId ||
    !validBase64Url(response.clientDataJSON) ||
    !validBase64Url(response.authenticatorData) ||
    !validBase64Url(response.signature) ||
    (response.userHandle !== undefined &&
      response.userHandle !== null &&
      !validBase64Url(response.userHandle))
  ) {
    return null;
  }

  return {
    id: value.id,
    rawId: value.rawId,
    response: {
      authenticatorData: response.authenticatorData,
      clientDataJSON: response.clientDataJSON,
      signature: response.signature,
      ...(typeof response.userHandle === "string"
        ? { userHandle: response.userHandle }
        : {}),
    },
    // PGID configures no authentication extensions for step-up. Ignore
    // untrusted client extension output instead of reflecting it downstream.
    clientExtensionResults: {},
    type: "public-key",
  };
}

function decodeStoredPublicKey(value: string): Uint8Array<ArrayBuffer> | null {
  try {
    const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
    const padded = normalized.padEnd(
      normalized.length + ((4 - (normalized.length % 4)) % 4),
      "=",
    );
    const binary = atob(padded);
    if (!binary) return null;
    const bytes = new Uint8Array(new ArrayBuffer(binary.length));
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return null;
  }
}

function sessionIsFresh(createdAt: string | Date): boolean {
  const timestamp = new Date(createdAt).getTime();
  const age = Date.now() - timestamp;
  return (
    Number.isFinite(timestamp) &&
    age >= 0 &&
    age < FRESH_SESSION_MAX_AGE_MS
  );
}

export async function readPasskeyStepUpState(
  env: Env,
  sessionId: string,
  userId: string,
  maxAgeMs: number,
): Promise<PasskeyStepUpState | null> {
  const row = await env.PG72_ID_DB.prepare(
    `SELECT s.passkeyStepUpAt AS verified_at,
            EXISTS(
              SELECT 1 FROM passkey p WHERE p.userId = s.userId LIMIT 1
            ) AS has_passkey
       FROM session s
      WHERE s.id = ? AND s.userId = ?
      LIMIT 1`,
  )
    .bind(sessionId, userId)
    .first<StepUpSessionRow>();
  if (!row) return null;

  const timestamp = row.verified_at
    ? new Date(row.verified_at).getTime()
    : Number.NaN;
  const age = Date.now() - timestamp;
  const verified =
    Number.isFinite(timestamp) && age >= 0 && age < maxAgeMs;

  return {
    expiresAt: Number.isFinite(timestamp)
      ? new Date(timestamp + maxAgeMs).toISOString()
      : null,
    hasPasskey: row.has_passkey === 1,
    verified,
    verifiedAt: row.verified_at,
  };
}

async function recordDeniedStepUp(
  env: Env,
  userId: string,
  reason: string,
  executionCtx: WaitUntilContext,
): Promise<void> {
  await recordAudit(
    env,
    {
      eventType: "passkey.step_up_failed",
      outcome: "denied",
      actorUserId: userId,
      subjectId: userId,
      metadata: { reason },
    },
    executionCtx,
  );
}

function auditInsertForCounterVerifiedSession(
  env: Env,
  event: SecurityEvent,
  sessionId: string,
  userId: string,
  passkeyId: string,
  counter: number,
): D1PreparedStatement {
  return env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, client_id, subject_id, outcome,
       metadata_json, occurred_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1 FROM session
         WHERE id = ? AND userId = ?
      ) AND EXISTS (
        SELECT 1 FROM passkey
         WHERE id = ? AND userId = ? AND counter = ?
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
    sessionId,
    userId,
    passkeyId,
    userId,
    counter,
  );
}

async function deleteOrphanedStepUpAudit(
  env: Env,
  auditEventId: string,
): Promise<void> {
  await env.PG72_ID_DB.prepare(
    `DELETE FROM audit_event
      WHERE id = ? AND event_type = 'passkey.step_up_succeeded'`,
  )
    .bind(auditEventId)
    .run();
}

export const passkeyStepUpRoutes = new Hono<AppEnv>();

passkeyStepUpRoutes.post(
  "/api/account/passkey-step-up/challenge",
  async (c) => {
    const auth = createAuth(c.env, c.executionCtx);
    const session = await auth.api.getSession({ headers: c.req.raw.headers });
    if (!session || session.user.status !== "active") {
      return c.json({ error: "unauthorized" }, 401);
    }
    if (!sessionIsFresh(session.session.createdAt)) {
      return c.json(
        {
          code: "SESSION_NOT_FRESH",
          error: "fresh_session_required",
        },
        403,
      );
    }

    const rateLimit = await c.env.AUTH_RATE_LIMITER.limit({
      key: session.user.id,
    });
    if (!rateLimit.success) {
      return c.json({ error: "rate_limited" }, 429);
    }

    const config = readRuntimeConfig(c.env);
    const state = await readPasskeyStepUpState(
      c.env,
      session.session.id,
      session.user.id,
      config.passkeyStepUpMaxAgeMs,
    );
    if (!state) return c.json({ error: "unauthorized" }, 401);
    if (!state.hasPasskey) {
      await recordDeniedStepUp(
        c.env,
        session.user.id,
        "passkey_not_enrolled",
        c.executionCtx,
      );
      return c.json(
        {
          code: "PASSKEY_ENROLLMENT_REQUIRED",
          error: "passkey_enrollment_required",
        },
        403,
      );
    }
    if (state.verified) {
      return c.json({
        expiresAt: state.expiresAt,
        maxAgeSeconds: config.passkeyStepUpMaxAgeMs / 1000,
        verified: true,
        verifiedAt: state.verifiedAt,
      });
    }

    const passkeys = await c.env.PG72_ID_DB.prepare(
      `SELECT credentialID FROM passkey
        WHERE userId = ?
        ORDER BY createdAt ASC, id ASC`,
    )
      .bind(session.user.id)
      .all<PasskeySummaryRow>();
    if (passkeys.results.length === 0) {
      return c.json(
        {
          code: "PASSKEY_ENROLLMENT_REQUIRED",
          error: "passkey_enrollment_required",
        },
        403,
      );
    }

    const options = await generateAuthenticationOptions({
      rpID: config.passkeyRpId,
      allowCredentials: passkeys.results.map((passkey) => ({
        id: passkey.credentialID,
      })),
      timeout: PASSKEY_STEP_UP_CHALLENGE_TTL_MS,
      userVerification: "required",
    });
    const challengeId = crypto.randomUUID();
    const now = new Date();
    const expiresAt = new Date(
      now.getTime() + PASSKEY_STEP_UP_CHALLENGE_TTL_MS,
    );

    await c.env.PG72_ID_DB.batch([
      c.env.PG72_ID_DB.prepare(
        `DELETE FROM passkey_step_up_challenge
          WHERE session_id = ? OR expires_at <= ?`,
      ).bind(session.session.id, now.toISOString()),
      c.env.PG72_ID_DB.prepare(
        `INSERT INTO passkey_step_up_challenge
          (id, session_id, user_id, challenge, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        challengeId,
        session.session.id,
        session.user.id,
        options.challenge,
        expiresAt.toISOString(),
        now.toISOString(),
      ),
    ]);

    return c.json({
      challengeId,
      maxAgeSeconds: config.passkeyStepUpMaxAgeMs / 1000,
      options,
      verified: false,
    });
  },
);

passkeyStepUpRoutes.post("/api/account/passkey-step-up/verify", async (c) => {
  const auth = createAuth(c.env, c.executionCtx);
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session || session.user.status !== "active") {
    return c.json({ error: "unauthorized" }, 401);
  }

  const rateLimit = await c.env.AUTH_RATE_LIMITER.limit({
    key: session.user.id,
  });
  if (!rateLimit.success) {
    return c.json({ error: "rate_limited" }, 429);
  }

  let input: unknown;
  try {
    input = await c.req.raw.json();
  } catch {
    return c.json({ error: "invalid_request" }, 400);
  }
  if (!isRecord(input) || !UUID_PATTERN.test(String(input.challengeId ?? ""))) {
    return c.json({ error: "invalid_request" }, 400);
  }
  const challengeId = String(input.challengeId);
  const assertion = parseAuthenticationResponse(input.response);
  if (!assertion) return c.json({ error: "invalid_request" }, 400);

  const now = new Date();
  const challenge = await c.env.PG72_ID_DB.prepare(
    `DELETE FROM passkey_step_up_challenge
      WHERE id = ? AND session_id = ? AND user_id = ? AND expires_at > ?
      RETURNING challenge`,
  )
    .bind(
      challengeId,
      session.session.id,
      session.user.id,
      now.toISOString(),
    )
    .first<StepUpChallengeRow>();
  if (!challenge) {
    await recordDeniedStepUp(
      c.env,
      session.user.id,
      "challenge_invalid",
      c.executionCtx,
    );
    return c.json({ error: "passkey_step_up_challenge_invalid" }, 400);
  }

  const passkey = await c.env.PG72_ID_DB.prepare(
    `SELECT id, credentialID, publicKey, counter
       FROM passkey
      WHERE credentialID = ? AND userId = ?
      LIMIT 1`,
  )
    .bind(assertion.id, session.user.id)
    .first<PasskeyVerificationRow>();
  const publicKey = passkey
    ? decodeStoredPublicKey(passkey.publicKey)
    : null;
  if (!passkey || !publicKey) {
    await recordDeniedStepUp(
      c.env,
      session.user.id,
      "credential_invalid",
      c.executionCtx,
    );
    return c.json({ error: "passkey_step_up_failed" }, 401);
  }

  const config = readRuntimeConfig(c.env);
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge: challenge.challenge,
      expectedOrigin: config.passkeyOrigin,
      expectedRPID: config.passkeyRpId,
      credential: {
        id: passkey.credentialID,
        publicKey,
        counter: passkey.counter,
      },
      requireUserVerification: true,
      advancedFIDOConfig: { userVerification: "required" },
    });
  } catch {
    await recordDeniedStepUp(
      c.env,
      session.user.id,
      "assertion_invalid",
      c.executionCtx,
    );
    return c.json({ error: "passkey_step_up_failed" }, 401);
  }
  if (!verification.verified || !verification.authenticationInfo.userVerified) {
    await recordDeniedStepUp(
      c.env,
      session.user.id,
      "user_verification_missing",
      c.executionCtx,
    );
    return c.json({ error: "passkey_step_up_failed" }, 401);
  }

  const newCounter = verification.authenticationInfo.newCounter;
  const counterUpdate = await c.env.PG72_ID_DB.prepare(
    `UPDATE passkey SET counter = ?
      WHERE id = ? AND userId = ? AND counter = ?`,
  )
    .bind(newCounter, passkey.id, session.user.id, passkey.counter)
    .run();
  if (counterUpdate.meta.changes !== 1) {
    await recordDeniedStepUp(
      c.env,
      session.user.id,
      "counter_conflict",
      c.executionCtx,
    );
    return c.json({ error: "passkey_step_up_failed" }, 409);
  }

  const verifiedAt = new Date().toISOString();
  const auditEvent = createAuditEvent({
    eventType: "passkey.step_up_succeeded",
    outcome: "success",
    actorUserId: session.user.id,
    subjectId: session.user.id,
    metadata: { method: "passkey" },
  });
  const results = await c.env.PG72_ID_DB.batch([
    auditInsertForCounterVerifiedSession(
      c.env,
      auditEvent,
      session.session.id,
      session.user.id,
      passkey.id,
      newCounter,
    ),
    c.env.PG72_ID_DB.prepare(
      `UPDATE session SET passkeyStepUpAt = ?
        WHERE id = ? AND userId = ?
          AND EXISTS (
            SELECT 1 FROM audit_event
             WHERE id = ?
               AND event_type = 'passkey.step_up_succeeded'
               AND actor_user_id = ?
               AND subject_id = ?
               AND outcome = 'success'
          )`,
    ).bind(
      verifiedAt,
      session.session.id,
      session.user.id,
      auditEvent.eventId,
      session.user.id,
      session.user.id,
    ),
  ]);
  if (results.every((result) => result.meta.changes === 1)) {
    await enqueueSecurityEvent(c.env, auditEvent, c.executionCtx);

    return c.json({
      expiresAt: new Date(
        new Date(verifiedAt).getTime() + config.passkeyStepUpMaxAgeMs,
      ).toISOString(),
      verified: true,
      verifiedAt,
    });
  }

  // A zero-change audit cannot unlock the session because the timestamp write
  // depends on that exact event. If the timestamp guard fails after the audit
  // insert, remove the harmless orphan; neither path exposes a valid step-up.
  await deleteOrphanedStepUpAudit(c.env, auditEvent.eventId);
  if (results[0]?.meta.changes !== 1) {
    const currentSession = await c.env.PG72_ID_DB.prepare(
      "SELECT 1 AS present FROM session WHERE id = ? AND userId = ?",
    )
      .bind(session.session.id, session.user.id)
      .first();
    if (currentSession) {
      throw new Error("Passkey step-up success audit was not persisted");
    }
    await recordDeniedStepUp(
      c.env,
      session.user.id,
      "session_invalidated",
      c.executionCtx,
    );
    return c.json({ error: "unauthorized" }, 401);
  }
  await recordDeniedStepUp(
    c.env,
    session.user.id,
    "session_invalidated",
    c.executionCtx,
  );
  return c.json({ error: "unauthorized" }, 401);
});
