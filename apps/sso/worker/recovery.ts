import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { Hono, type Context } from "hono";

import {
  auditEventMutationCommitted,
  createAuditEvent,
  enqueueSecurityEvent,
  recordAudit,
  type SecurityEvent,
} from "./audit";
import {
  RECOVERY_CODE_COUNT,
  RECOVERY_FORMAT_VERSION,
  RECOVERY_PASSKEY_CHALLENGE_TTL_MS,
  RECOVERY_SESSION_TTL_MS,
  readRuntimeConfig,
} from "./config";
import {
  globalLogoutForUserStatements,
  scheduleLogoutDeliveryDispatch,
} from "./global-logout";
import {
  canonicalRecoveryCode,
  generateRecoveryCodeSet,
  isStrictRecoveryJsonMediaType,
  sha256Base64Url,
} from "./recovery-codes";
import { recoveryDisabledResponse } from "./recovery-gate";

type AppEnv = { Bindings: Env };

const RECOVERY_COOKIE = "__Secure-pg72_recovery";
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const REGISTRATION_FIELD_MAX_LENGTH = 16 * 1024;
const CREDENTIAL_ID_MAX_BYTES = 1023;
const CREDENTIAL_ID_MAX_ENCODED_LENGTH = Math.ceil(
  (CREDENTIAL_ID_MAX_BYTES * 4) / 3,
);
const DUMMY_CANONICAL_CODE = `PGIDR${RECOVERY_FORMAT_VERSION}${"0".repeat(32)}`;
const DUMMY_RECOVERY_TOKEN = "0".repeat(43);
const ALLOWED_TRANSPORTS: ReadonlySet<AuthenticatorTransportFuture> = new Set([
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb",
]);

interface RecoveryCodeLookupRow {
  code_id: string;
  generation: number;
  set_id: string;
  user_id: string;
}

interface RecoverySessionRow {
  code_set_id: string;
  expires_at: string;
  generation: number;
  id: string;
  source_code_id: string;
  user_id: string;
}

interface RecoveryChallengeRow {
  challenge: string;
}

interface ExistingPasskeyRow {
  credentialID: string;
  transports: string | null;
}

interface RecoveryVerifyInput {
  challengeId: string;
  response: RegistrationResponseJSON | null;
}

function noStoreHeaders(c: Context<AppEnv>): void {
  c.header("Cache-Control", "no-store");
  c.header("Pragma", "no-cache");
}

function cookieValue(headers: Headers): string | null {
  const matches = (headers.get("cookie") ?? "")
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${RECOVERY_COOKIE}=`));
  if (matches.length !== 1) return null;
  const value = matches[0]?.slice(RECOVERY_COOKIE.length + 1) ?? "";
  return value.length === 43 && BASE64URL_PATTERN.test(value) ? value : null;
}

function recoveryCookie(token: string): string {
  return `${RECOVERY_COOKIE}=${token}; Path=/api/recovery; Max-Age=600; HttpOnly; Secure; SameSite=Strict`;
}

function clearRecoveryCookie(): string {
  return `${RECOVERY_COOKIE}=; Path=/api/recovery; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

function bytesToBase64Url(bytes: Uint8Array<ArrayBuffer>): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function randomToken(): string {
  return bytesToBase64Url(
    crypto.getRandomValues(new Uint8Array(new ArrayBuffer(32))),
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, keys: string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

async function isEmptyJsonObject(request: Request): Promise<boolean> {
  if (!isStrictRecoveryJsonMediaType(request.headers.get("content-type"))) {
    return false;
  }
  try {
    const value: unknown = await request.json();
    return isRecord(value) && Object.keys(value).length === 0;
  } catch {
    return false;
  }
}

function boundedBase64Url(
  value: unknown,
  maximum = REGISTRATION_FIELD_MAX_LENGTH,
): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    BASE64URL_PATTERN.test(value)
  );
}

function decodedCredentialId(value: unknown): Uint8Array<ArrayBuffer> | null {
  if (!boundedBase64Url(value, CREDENTIAL_ID_MAX_ENCODED_LENGTH)) return null;
  try {
    const bytes = isoBase64URL.toBuffer(value);
    if (
      bytes.byteLength === 0 ||
      bytes.byteLength > CREDENTIAL_ID_MAX_BYTES ||
      isoBase64URL.fromBuffer(bytes) !== value
    ) {
      return null;
    }
    return new Uint8Array(bytes);
  } catch {
    return null;
  }
}

function validCredentialId(value: unknown): value is string {
  return decodedCredentialId(value) !== null;
}

function matchingCredentialIds(
  outerRawId: string,
  verifiedCredentialId: string,
): boolean {
  const outer = decodedCredentialId(outerRawId);
  const verified = decodedCredentialId(verifiedCredentialId);
  return (
    outer !== null &&
    verified !== null &&
    outer.byteLength === verified.byteLength &&
    outer.every((byte, index) => byte === verified[index])
  );
}

function parseTransports(value: unknown): AuthenticatorTransportFuture[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 8) return null;
  const transports: AuthenticatorTransportFuture[] = [];
  for (const transport of value) {
    if (
      typeof transport !== "string" ||
      !ALLOWED_TRANSPORTS.has(transport as AuthenticatorTransportFuture)
    ) {
      return null;
    }
    transports.push(transport as AuthenticatorTransportFuture);
  }
  return transports;
}

function parseRegistrationResponse(value: unknown): RegistrationResponseJSON | null {
  if (!isRecord(value) || !isRecord(value.response)) return null;
  const response = value.response;
  const transports = parseTransports(response.transports);
  if (
    value.type !== "public-key" ||
    !validCredentialId(value.id) ||
    !validCredentialId(value.rawId) ||
    value.id !== value.rawId ||
    !boundedBase64Url(response.clientDataJSON) ||
    !boundedBase64Url(response.attestationObject) ||
    transports === null
  ) {
    return null;
  }
  return {
    id: value.id,
    rawId: value.rawId,
    response: {
      clientDataJSON: response.clientDataJSON,
      attestationObject: response.attestationObject,
      ...(transports.length > 0 ? { transports } : {}),
    },
    clientExtensionResults: {},
    type: "public-key",
  };
}

async function parseVerifyInput(request: Request): Promise<RecoveryVerifyInput | null> {
  if (!isStrictRecoveryJsonMediaType(request.headers.get("content-type"))) {
    return null;
  }
  let value: unknown;
  try {
    value = await request.json();
  } catch {
    return null;
  }
  if (!isRecord(value) || !hasOnlyKeys(value, ["challengeId", "response"])) {
    return null;
  }
  if (typeof value.challengeId !== "string" || !UUID_PATTERN.test(value.challengeId)) {
    return null;
  }
  return {
    challengeId: value.challengeId,
    response: parseRegistrationResponse(value.response),
  };
}

async function recoveryLimit(c: Context<AppEnv>): Promise<Response | null> {
  const ip = c.req.header("cf-connecting-ip") ?? "local";
  try {
    const result = await c.env.RECOVERY_RATE_LIMITER.limit({
      key: `recovery:${ip}`,
    });
    if (result.success) return null;
    await recordAudit(
      c.env,
      {
        eventType: "recovery.rate_limited",
        outcome: "denied",
        metadata: { surface: "recovery" },
      },
      c.executionCtx,
    );
    return c.json({ error: "recovery_rate_limited" }, 429);
  } catch {
    return c.json({ error: "recovery_temporarily_unavailable" }, 503);
  }
}

async function recordEntryDenied(c: Context<AppEnv>): Promise<void> {
  await recordAudit(
    c.env,
    {
      eventType: "recovery.entry_denied",
      outcome: "denied",
      metadata: { formatVersion: RECOVERY_FORMAT_VERSION },
    },
    c.executionCtx,
  );
}

async function recordPasskeyFailure(
  c: Context<AppEnv>,
  userId: string,
  reason: string,
): Promise<void> {
  await recordAudit(
    c.env,
    {
      eventType: "recovery.passkey_failed",
      outcome: "denied",
      subjectId: userId,
      metadata: { reason },
    },
    c.executionCtx,
  );
}

async function recoverySession(
  env: Env,
  token: string | null,
  now: string,
): Promise<RecoverySessionRow | null> {
  const tokenHash = await sha256Base64Url(token ?? DUMMY_RECOVERY_TOKEN);
  return env.PG72_ID_DB.prepare(
    `SELECT recovery_session.id, recovery_session.user_id,
            recovery_session.code_set_id, recovery_session.source_code_id,
            recovery_session.expires_at, recovery_code_set.generation
       FROM recovery_session
       JOIN recovery_code_set
         ON recovery_code_set.id = recovery_session.code_set_id
       JOIN user ON user.id = recovery_session.user_id
      WHERE recovery_session.token_hash = ?
        AND recovery_session.expires_at > ?
        AND user.status = 'active'
        AND recovery_code_set.revoked_at IS NULL
        AND (
          recovery_code_set.expires_at IS NULL
          OR recovery_code_set.expires_at > ?
        )
      LIMIT 1`,
  )
    .bind(tokenHash, now, now)
    .first<RecoverySessionRow>();
}

function recoverySessionUnavailable(c: Context<AppEnv>): Response {
  c.header("Set-Cookie", clearRecoveryCookie());
  return c.json({ error: "recovery_session_unavailable" }, 401);
}

function recoveryCompletionPasskeyStatement(
  env: Env,
  input: {
    aaguid: string;
    backedUp: boolean;
    counter: number;
    credentialId: string;
    deviceType: string;
    name: string;
    now: string;
    passkeyId: string;
    publicKey: string;
    session: RecoverySessionRow;
    tokenHash: string;
    transports: string;
  },
): D1PreparedStatement {
  return env.PG72_ID_DB.prepare(
    `INSERT INTO passkey
      (id, name, publicKey, userId, credentialID, counter, deviceType,
       backedUp, transports, createdAt, aaguid)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1
          FROM recovery_session
          JOIN user ON user.id = recovery_session.user_id
          JOIN recovery_code_set
            ON recovery_code_set.id = recovery_session.code_set_id
         WHERE recovery_session.id = ?
           AND recovery_session.token_hash = ?
           AND recovery_session.user_id = ?
           AND recovery_session.code_set_id = ?
           AND recovery_session.source_code_id = ?
           AND recovery_session.expires_at > ?
           AND user.status = 'active'
           AND recovery_code_set.revoked_at IS NULL
           AND (
             recovery_code_set.expires_at IS NULL
             OR recovery_code_set.expires_at > ?
           )
           AND NOT EXISTS (
             SELECT 1 FROM recovery_passkey_challenge
              WHERE recovery_session_id = recovery_session.id
           )
      )
        AND NOT EXISTS (
          SELECT 1 FROM passkey WHERE credentialID = ?
        )`,
  ).bind(
    input.passkeyId,
    input.name,
    input.publicKey,
    input.session.user_id,
    input.credentialId,
    input.counter,
    input.deviceType,
    input.backedUp ? 1 : 0,
    input.transports,
    input.now,
    input.aaguid,
    input.session.id,
    input.tokenHash,
    input.session.user_id,
    input.session.code_set_id,
    input.session.source_code_id,
    input.now,
    input.now,
    input.credentialId,
  );
}

function recoveryCompletionAuditStatement(
  env: Env,
  event: SecurityEvent,
  input: {
    credentialId: string;
    passkeyId: string;
    session: RecoverySessionRow;
    tokenHash: string;
    now: string;
  },
): D1PreparedStatement {
  return env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, client_id, subject_id, outcome,
       metadata_json, occurred_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1 FROM passkey
         WHERE id = ? AND userId = ? AND credentialID = ?
      )
        AND EXISTS (
          SELECT 1 FROM recovery_session
           WHERE id = ? AND token_hash = ? AND user_id = ?
             AND code_set_id = ? AND expires_at > ?
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
    input.passkeyId,
    input.session.user_id,
    input.credentialId,
    input.session.id,
    input.tokenHash,
    input.session.user_id,
    input.session.code_set_id,
    input.now,
  );
}

export const recoveryRoutes = new Hono<AppEnv>();

recoveryRoutes.post("/api/recovery/start", async (c) => {
  noStoreHeaders(c);
  const disabled = recoveryDisabledResponse(c);
  if (disabled) return disabled;
  const limited = await recoveryLimit(c);
  if (limited) return limited;

  let body: unknown = null;
  if (isStrictRecoveryJsonMediaType(c.req.header("content-type") ?? null)) {
    try {
      body = await c.req.raw.json();
    } catch {
      body = null;
    }
  }
  const input = isRecord(body) && hasOnlyKeys(body, ["code"]) ? body.code : null;
  const canonical = canonicalRecoveryCode(input);
  const codeHash = await sha256Base64Url(canonical ?? DUMMY_CANONICAL_CODE);
  const candidate = await c.env.PG72_ID_DB.prepare(
    `SELECT recovery_code.id AS code_id,
            recovery_code_set.id AS set_id,
            recovery_code_set.user_id,
            recovery_code_set.generation
       FROM recovery_code
       JOIN recovery_code_set ON recovery_code_set.id = recovery_code.set_id
      WHERE recovery_code.code_hash = ?
      LIMIT 1`,
  )
    .bind(codeHash)
    .first<RecoveryCodeLookupRow>();

  const token = randomToken();
  const tokenHash = await sha256Base64Url(token);
  const sessionId = crypto.randomUUID();
  const nowDate = new Date();
  const now = nowDate.toISOString();
  const expiresAt = new Date(
    nowDate.getTime() + RECOVERY_SESSION_TTL_MS,
  ).toISOString();
  const codeId = candidate?.code_id ?? crypto.randomUUID();
  const setId = candidate?.set_id ?? crypto.randomUUID();
  const userId = candidate?.user_id ?? crypto.randomUUID();
  const event = createAuditEvent({
    eventType: "recovery.started",
    outcome: "success",
    subjectId: candidate?.user_id,
    metadata: {
      formatVersion: RECOVERY_FORMAT_VERSION,
      generation: candidate?.generation ?? 0,
    },
  });
  const results = await c.env.PG72_ID_DB.batch([
    c.env.PG72_ID_DB.prepare(
      "DELETE FROM recovery_session WHERE user_id = ? AND expires_at <= ?",
    ).bind(userId, now),
    c.env.PG72_ID_DB.prepare(
      `INSERT INTO audit_event
        (id, event_type, actor_user_id, client_id, subject_id, outcome,
         metadata_json, occurred_at)
       SELECT ?, ?, NULL, NULL, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1
            FROM recovery_code
            JOIN recovery_code_set
              ON recovery_code_set.id = recovery_code.set_id
            JOIN user ON user.id = recovery_code_set.user_id
           WHERE recovery_code.id = ?
             AND recovery_code.code_hash = ?
             AND recovery_code.consumed_at IS NULL
             AND recovery_code_set.id = ?
             AND recovery_code_set.user_id = ?
             AND recovery_code_set.revoked_at IS NULL
             AND (
               recovery_code_set.expires_at IS NULL
               OR recovery_code_set.expires_at > ?
             )
             AND user.status = 'active'
             AND NOT EXISTS (
               SELECT 1 FROM recovery_session
                WHERE user_id = user.id AND expires_at > ?
             )
        )`,
    ).bind(
      event.eventId,
      event.eventType,
      candidate?.user_id ?? null,
      event.outcome,
      event.metadata ? JSON.stringify(event.metadata) : null,
      event.occurredAt,
      codeId,
      codeHash,
      setId,
      userId,
      now,
      now,
    ),
    c.env.PG72_ID_DB.prepare(
      `UPDATE recovery_code SET consumed_at = ?
        WHERE id = ? AND set_id = ? AND code_hash = ?
          AND consumed_at IS NULL
          AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
    ).bind(now, codeId, setId, codeHash, event.eventId),
    c.env.PG72_ID_DB.prepare(
      `INSERT INTO recovery_session
        (id, token_hash, user_id, code_set_id, source_code_id,
         created_at, expires_at)
       SELECT ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (SELECT 1 FROM audit_event WHERE id = ?)
          AND EXISTS (
            SELECT 1 FROM recovery_code
             WHERE id = ? AND set_id = ? AND consumed_at = ?
          )`,
    ).bind(
      sessionId,
      tokenHash,
      userId,
      setId,
      codeId,
      now,
      expiresAt,
      event.eventId,
      codeId,
      setId,
      now,
    ),
  ]);
  const started =
    auditEventMutationCommitted(results[1]) &&
    (results[2]?.meta.changes ?? 0) >= 1 &&
    results[3]?.meta.changes === 1;
  if (!started) {
    await recordEntryDenied(c);
    return c.json({ error: "recovery_not_available" }, 400);
  }

  await enqueueSecurityEvent(c.env, event, c.executionCtx);
  c.header("Set-Cookie", recoveryCookie(token));
  return c.json({ active: true, expiresAt });
});

recoveryRoutes.get("/api/recovery/session", async (c) => {
  noStoreHeaders(c);
  const disabled = recoveryDisabledResponse(c);
  if (disabled) return disabled;
  const now = new Date().toISOString();
  const session = await recoverySession(c.env, cookieValue(c.req.raw.headers), now);
  if (!session) return recoverySessionUnavailable(c);
  return c.json({ active: true, expiresAt: session.expires_at });
});

recoveryRoutes.delete("/api/recovery/session", async (c) => {
  noStoreHeaders(c);
  const disabled = recoveryDisabledResponse(c);
  if (disabled) return disabled;
  const token = cookieValue(c.req.raw.headers);
  const tokenHash = await sha256Base64Url(token ?? DUMMY_RECOVERY_TOKEN);
  await c.env.PG72_ID_DB.prepare(
    "DELETE FROM recovery_session WHERE token_hash = ?",
  )
    .bind(tokenHash)
    .run();
  c.header("Set-Cookie", clearRecoveryCookie());
  return c.json({ cancelled: true });
});

recoveryRoutes.post("/api/recovery/passkey/options", async (c) => {
  noStoreHeaders(c);
  const disabled = recoveryDisabledResponse(c);
  if (disabled) return disabled;
  if (!isStrictRecoveryJsonMediaType(c.req.header("content-type") ?? null)) {
    return c.json({ error: "invalid_request" }, 415);
  }
  if (!(await isEmptyJsonObject(c.req.raw))) {
    return c.json({ error: "invalid_request" }, 400);
  }
  const nowDate = new Date();
  const now = nowDate.toISOString();
  const session = await recoverySession(c.env, cookieValue(c.req.raw.headers), now);
  if (!session) return recoverySessionUnavailable(c);

  const config = readRuntimeConfig(c.env);
  const existing = await c.env.PG72_ID_DB.prepare(
    `SELECT credentialID, transports FROM passkey
      WHERE userId = ? ORDER BY createdAt ASC, id ASC`,
  )
    .bind(session.user_id)
    .all<ExistingPasskeyRow>();
  const options = await generateRegistrationOptions({
    rpName: "PGID",
    rpID: config.passkeyRpId,
    userID: new TextEncoder().encode(session.user_id),
    userName: session.user_id,
    userDisplayName: "PGID account",
    timeout: RECOVERY_PASSKEY_CHALLENGE_TTL_MS,
    attestationType: "none",
    excludeCredentials: existing.results.map((passkey) => ({
      id: passkey.credentialID,
      ...(passkey.transports
        ? {
            transports: passkey.transports
              .split(",")
              .filter((value): value is AuthenticatorTransportFuture =>
                ALLOWED_TRANSPORTS.has(value as AuthenticatorTransportFuture),
              ),
          }
        : {}),
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "required",
    },
  });
  const challengeId = crypto.randomUUID();
  const expiresAt = new Date(
    nowDate.getTime() + RECOVERY_PASSKEY_CHALLENGE_TTL_MS,
  ).toISOString();
  const results = await c.env.PG72_ID_DB.batch([
    c.env.PG72_ID_DB.prepare(
      `DELETE FROM recovery_passkey_challenge
        WHERE recovery_session_id = ? OR expires_at <= ?`,
    ).bind(session.id, now),
    c.env.PG72_ID_DB.prepare(
      `INSERT INTO recovery_passkey_challenge
        (id, recovery_session_id, challenge, created_at, expires_at)
       SELECT ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1
            FROM recovery_session
            JOIN recovery_code_set
              ON recovery_code_set.id = recovery_session.code_set_id
            JOIN user ON user.id = recovery_session.user_id
           WHERE recovery_session.id = ?
             AND recovery_session.user_id = ?
             AND recovery_session.expires_at > ?
             AND user.status = 'active'
             AND recovery_code_set.revoked_at IS NULL
             AND (
               recovery_code_set.expires_at IS NULL
               OR recovery_code_set.expires_at > ?
             )
        )`,
    ).bind(
      challengeId,
      session.id,
      options.challenge,
      now,
      expiresAt,
      session.id,
      session.user_id,
      now,
      now,
    ),
  ]);
  if (results[1]?.meta.changes !== 1) {
    c.header("Set-Cookie", clearRecoveryCookie());
    return c.json({ error: "recovery_session_unavailable" }, 401);
  }
  return c.json({ challengeId, options, expiresAt });
});

recoveryRoutes.post("/api/recovery/passkey/verify", async (c) => {
  noStoreHeaders(c);
  const disabled = recoveryDisabledResponse(c);
  if (disabled) return disabled;
  const now = new Date().toISOString();
  const token = cookieValue(c.req.raw.headers);
  const session = await recoverySession(c.env, token, now);
  if (!session) return recoverySessionUnavailable(c);
  const input = await parseVerifyInput(c.req.raw);
  if (!input) {
    await recordPasskeyFailure(c, session.user_id, "invalid_request");
    return c.json({ error: "recovery_passkey_failed" }, 400);
  }
  const tokenHash = await sha256Base64Url(token ?? DUMMY_RECOVERY_TOKEN);
  const challenge = await c.env.PG72_ID_DB.prepare(
    `DELETE FROM recovery_passkey_challenge
      WHERE id = ?
        AND recovery_session_id = (
          SELECT recovery_session.id
            FROM recovery_session
            JOIN recovery_code_set
              ON recovery_code_set.id = recovery_session.code_set_id
            JOIN user ON user.id = recovery_session.user_id
           WHERE recovery_session.id = ?
             AND recovery_session.token_hash = ?
             AND recovery_session.user_id = ?
             AND recovery_session.expires_at > ?
             AND user.status = 'active'
             AND recovery_code_set.revoked_at IS NULL
             AND (
               recovery_code_set.expires_at IS NULL
               OR recovery_code_set.expires_at > ?
             )
        )
        AND expires_at > ?
      RETURNING challenge`,
  )
    .bind(
      input.challengeId,
      session.id,
      tokenHash,
      session.user_id,
      now,
      now,
      now,
    )
    .first<RecoveryChallengeRow>();
  if (!challenge) {
    await recordPasskeyFailure(c, session.user_id, "challenge_invalid");
    return c.json({ error: "recovery_passkey_failed" }, 400);
  }
  if (!input.response) {
    await recordPasskeyFailure(c, session.user_id, "invalid_request");
    return c.json({ error: "recovery_passkey_failed" }, 400);
  }

  const config = readRuntimeConfig(c.env);
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: input.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: config.passkeyOrigin,
      expectedRPID: config.passkeyRpId,
      requireUserVerification: true,
    });
  } catch {
    await recordPasskeyFailure(c, session.user_id, "attestation_invalid");
    return c.json({ error: "recovery_passkey_failed" }, 400);
  }
  if (!verification.verified || !verification.registrationInfo.userVerified) {
    await recordPasskeyFailure(c, session.user_id, "user_verification_missing");
    return c.json({ error: "recovery_passkey_failed" }, 400);
  }

  const credential = verification.registrationInfo.credential;
  if (!matchingCredentialIds(input.response.rawId, credential.id)) {
    await recordPasskeyFailure(c, session.user_id, "credential_id_invalid");
    return c.json({ error: "recovery_passkey_failed" }, 400);
  }

  const generated = await generateRecoveryCodeSet();
  const finalNow = new Date().toISOString();
  const passkeyId = crypto.randomUUID();
  const nextSetId = crypto.randomUUID();
  const nextGeneration = session.generation + 1;
  const event = createAuditEvent({
    eventType: "recovery.completed",
    outcome: "success",
    subjectId: session.user_id,
    metadata: {
      count: RECOVERY_CODE_COUNT,
      formatVersion: RECOVERY_FORMAT_VERSION,
      generation: nextGeneration,
      method: "passkey",
    },
  });
  const statements: D1PreparedStatement[] = [
    recoveryCompletionPasskeyStatement(c.env, {
      aaguid: verification.registrationInfo.aaguid,
      backedUp: verification.registrationInfo.credentialBackedUp,
      counter: credential.counter,
      credentialId: credential.id,
      deviceType: verification.registrationInfo.credentialDeviceType,
      name: "Recovered Passkey",
      now: finalNow,
      passkeyId,
      publicKey: isoBase64URL.fromBuffer(credential.publicKey, "base64"),
      session,
      tokenHash,
      transports: input.response.response.transports?.join(",") ?? "",
    }),
    recoveryCompletionAuditStatement(c.env, event, {
      credentialId: credential.id,
      passkeyId,
      session,
      tokenHash,
      now: finalNow,
    }),
    c.env.PG72_ID_DB.prepare(
      `UPDATE recovery_code_set SET revoked_at = ?
        WHERE id = ? AND user_id = ? AND generation = ? AND revoked_at IS NULL
          AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)
          AND EXISTS (
            SELECT 1 FROM passkey
             WHERE id = ? AND userId = ? AND credentialID = ?
          )`,
    ).bind(
      finalNow,
      session.code_set_id,
      session.user_id,
      session.generation,
      event.eventId,
      passkeyId,
      session.user_id,
      credential.id,
    ),
    c.env.PG72_ID_DB.prepare(
      `INSERT INTO recovery_code_set
        (id, user_id, generation, format_version, created_at, expires_at)
       SELECT ?, ?, ?, ?, ?, NULL
        WHERE EXISTS (SELECT 1 FROM audit_event WHERE id = ?)
          AND EXISTS (
            SELECT 1 FROM passkey
             WHERE id = ? AND userId = ? AND credentialID = ?
          )`,
    ).bind(
      nextSetId,
      session.user_id,
      nextGeneration,
      RECOVERY_FORMAT_VERSION,
      finalNow,
      event.eventId,
      passkeyId,
      session.user_id,
      credential.id,
    ),
  ];
  generated.hashes.forEach((hash, index) => {
    statements.push(
      c.env.PG72_ID_DB.prepare(
        `INSERT INTO recovery_code
          (id, set_id, ordinal, code_hash, consumed_at)
         SELECT ?, ?, ?, ?, NULL
          WHERE EXISTS (
            SELECT 1 FROM recovery_code_set
             WHERE id = ? AND user_id = ? AND revoked_at IS NULL
          )
            AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
      ).bind(
        crypto.randomUUID(),
        nextSetId,
        index + 1,
        hash,
        nextSetId,
        session.user_id,
        event.eventId,
      ),
    );
  });
  statements.push(
    ...globalLogoutForUserStatements(c.env, {
      eventId: event.eventId,
      now: finalNow,
      reason: "self_revoke",
      userId: session.user_id,
    }),
    c.env.PG72_ID_DB.prepare(
      `DELETE FROM verification
        WHERE json_valid(value)
          AND json_extract(value, '$.userId') = ?
          AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
    ).bind(session.user_id, event.eventId),
    c.env.PG72_ID_DB.prepare(
      `DELETE FROM session
        WHERE userId = ?
          AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)
        RETURNING id`,
    ).bind(session.user_id, event.eventId),
  );

  const results = await c.env.PG72_ID_DB.batch(statements);
  const codeStart = 4;
  const codeEnd = codeStart + RECOVERY_CODE_COUNT;
  const completed =
    results[0]?.meta.changes === 1 &&
    auditEventMutationCommitted(results[1]) &&
    (results[2]?.meta.changes ?? 0) >= 1 &&
    results[3]?.meta.changes === 1 &&
    results.slice(codeStart, codeEnd).every((result) => result.meta.changes === 1);
  if (!completed) {
    console.error(
      JSON.stringify({
        event: "recovery_completion_state_changed",
        changes: results.map((result) => result.meta.changes),
      }),
    );
    await recordPasskeyFailure(c, session.user_id, "state_changed");
    return c.json({ error: "recovery_passkey_failed" }, 409);
  }

  await enqueueSecurityEvent(c.env, event, c.executionCtx);
  await scheduleLogoutDeliveryDispatch(c.env, c.executionCtx);
  c.header("Set-Cookie", clearRecoveryCookie());
  return c.json({
    completed: true,
    signInRequired: true,
    codes: generated.codes,
    count: RECOVERY_CODE_COUNT,
    expiresAt: null,
    formatVersion: RECOVERY_FORMAT_VERSION,
    generation: nextGeneration,
  });
});
