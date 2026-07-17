import { Hono, type Context } from "hono";

import {
  createAuditEvent,
  enqueueSecurityEvent,
  type SecurityEvent,
} from "./audit";
import { createAuth } from "./auth";
import {
  FRESH_SESSION_MAX_AGE_MS,
  RECOVERY_CODE_COUNT,
  RECOVERY_FORMAT_VERSION,
  readRuntimeConfig,
} from "./config";

type AppEnv = { Bindings: Env };

const RECOVERY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RECOVERY_PAYLOAD_PATTERN = /^[0-9A-HJKMNP-TV-Z]{32}$/;
const RECOVERY_INPUT_PATTERN = /^[A-Za-z0-9 -]+$/;

interface RecoveryCodeSetRow {
  expires_at: string | null;
  generation: number;
  id: string;
  remaining: number;
}

interface ManagementSnapshot {
  active_set_expires_at: string | null;
  active_set_generation: number | null;
  active_set_id: string | null;
  active_set_remaining: number;
  created_at: string;
  expires_at: string;
  max_generation: number;
  passkey_count: number;
  passkey_step_up_at: string | null;
  status: string;
}

export function isStrictRecoveryJsonMediaType(value: string | null): boolean {
  if (!value) return false;
  const parts = value.split(";");
  if (parts.shift()?.trim().toLowerCase() !== "application/json") return false;
  if (parts.length === 0) return true;
  if (parts.length !== 1) return false;
  const parameter = parts[0]?.trim() ?? "";
  const separator = parameter.indexOf("=");
  if (separator < 0 || parameter.indexOf("=", separator + 1) >= 0) return false;
  const name = parameter.slice(0, separator).trim().toLowerCase();
  const rawValue = parameter.slice(separator + 1).trim().toLowerCase();
  return (
    name === "charset" && (rawValue === "utf-8" || rawValue === '"utf-8"')
  );
}

async function isEmptyJsonObject(request: Request): Promise<boolean> {
  if (!isStrictRecoveryJsonMediaType(request.headers.get("content-type"))) {
    return false;
  }
  try {
    const value: unknown = await request.json();
    return (
      typeof value === "object" &&
      value !== null &&
      !Array.isArray(value) &&
      Object.keys(value).length === 0
    );
  } catch {
    return false;
  }
}

export interface GeneratedRecoveryCodeSet {
  codes: string[];
  hashes: string[];
}

function bytesToBase64Url(bytes: Uint8Array<ArrayBuffer>): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

export function canonicalRecoveryCode(value: unknown): string | null {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 128 ||
    !RECOVERY_INPUT_PATTERN.test(value)
  ) {
    return null;
  }
  const compact = value.replaceAll("-", "").replaceAll(" ", "").toUpperCase();
  if (!compact.startsWith("PGIDR1")) return null;
  const payload = compact.slice(6);
  return RECOVERY_PAYLOAD_PATTERN.test(payload) ? compact : null;
}

function encodeRecoveryPayload(bytes: Uint8Array<ArrayBuffer>): string {
  if (bytes.length !== 20) throw new Error("Recovery entropy must be 20 bytes");
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += RECOVERY_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits !== 0 || output.length !== 32) {
    throw new Error("Recovery entropy encoding failed");
  }
  return output;
}

function displayRecoveryCode(payload: string): string {
  return `PGID-R1-${payload.match(/.{4}/g)?.join("-") ?? payload}`;
}

export async function generateRecoveryCodeSet(): Promise<GeneratedRecoveryCodeSet> {
  const codes: string[] = [];
  const hashes: string[] = [];
  const canonicalValues = new Set<string>();
  while (codes.length < RECOVERY_CODE_COUNT) {
    const entropy = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(20)));
    const payload = encodeRecoveryPayload(entropy);
    const canonical = `PGIDR${RECOVERY_FORMAT_VERSION}${payload}`;
    if (canonicalValues.has(canonical)) continue;
    canonicalValues.add(canonical);
    codes.push(displayRecoveryCode(payload));
    hashes.push(await sha256Base64Url(canonical));
  }
  return { codes, hashes };
}

function noStoreHeaders(c: Context<AppEnv>): void {
  c.header("Cache-Control", "no-store");
  c.header("Pragma", "no-cache");
}

function recoveryDisabled(c: Context<AppEnv>): Response | null {
  return readRuntimeConfig(c.env).recoveryEnabled
    ? null
    : c.json({ error: "not_found" }, 404);
}

async function loadManagementSnapshot(
  env: Env,
  sessionId: string,
  userId: string,
): Promise<ManagementSnapshot | null> {
  return env.PG72_ID_DB.prepare(
    `SELECT session.createdAt AS created_at,
            session.expiresAt AS expires_at,
            session.passkeyStepUpAt AS passkey_step_up_at,
            user.status,
            (SELECT COUNT(*) FROM passkey WHERE userId = user.id)
              AS passkey_count,
            active.id AS active_set_id,
            active.generation AS active_set_generation,
            active.expires_at AS active_set_expires_at,
            COALESCE((
              SELECT COUNT(*) FROM recovery_code
               WHERE set_id = active.id AND consumed_at IS NULL
            ), 0) AS active_set_remaining,
            COALESCE((
              SELECT MAX(generation) FROM recovery_code_set
               WHERE user_id = user.id
            ), 0) AS max_generation
       FROM session
       JOIN user ON user.id = session.userId
       LEFT JOIN recovery_code_set AS active
         ON active.user_id = user.id AND active.revoked_at IS NULL
      WHERE session.id = ? AND session.userId = ?
      LIMIT 1`,
  )
    .bind(sessionId, userId)
    .first<ManagementSnapshot>();
}

function mutationSnapshotEligible(
  snapshot: ManagementSnapshot,
  nowMs: number,
  stepUpMaxAgeMs: number,
): "fresh_session_required" | "passkey_enrollment_required" | "passkey_step_up_required" | null {
  const createdAt = new Date(snapshot.created_at).getTime();
  const expiresAt = new Date(snapshot.expires_at).getTime();
  const sessionAge = nowMs - createdAt;
  if (
    !Number.isFinite(createdAt) ||
    !Number.isFinite(expiresAt) ||
    sessionAge < 0 ||
    sessionAge >= FRESH_SESSION_MAX_AGE_MS ||
    expiresAt <= nowMs
  ) {
    return "fresh_session_required";
  }
  if (snapshot.passkey_count < 1) return "passkey_enrollment_required";
  const verifiedAt = snapshot.passkey_step_up_at
    ? new Date(snapshot.passkey_step_up_at).getTime()
    : Number.NaN;
  const stepUpAge = nowMs - verifiedAt;
  if (
    !Number.isFinite(verifiedAt) ||
    stepUpAge < 0 ||
    stepUpAge >= stepUpMaxAgeMs
  ) {
    return "passkey_step_up_required";
  }
  return null;
}

function managementCommitPredicate(): string {
  return `EXISTS (
    SELECT 1
      FROM session AS recovery_actor_session
      JOIN user AS recovery_actor
        ON recovery_actor.id = recovery_actor_session.userId
     WHERE recovery_actor_session.id = ?
       AND recovery_actor_session.userId = ?
       AND recovery_actor.status = 'active'
       AND recovery_actor_session.expiresAt > ?
       AND recovery_actor_session.createdAt <= ?
       AND recovery_actor_session.createdAt > ?
       AND recovery_actor_session.passkeyStepUpAt IS NOT NULL
       AND recovery_actor_session.passkeyStepUpAt <= ?
       AND recovery_actor_session.passkeyStepUpAt > ?
       AND EXISTS (
         SELECT 1 FROM passkey
          WHERE userId = recovery_actor.id
       )
  )`;
}

function managementCommitBindings(
  sessionId: string,
  userId: string,
  now: string,
  freshAfter: string,
  stepUpAfter: string,
): unknown[] {
  return [sessionId, userId, now, now, freshAfter, now, stepUpAfter];
}

function managementAuditStatement(
  env: Env,
  event: SecurityEvent,
  input: {
    activeSetId: string | null;
    maxGeneration: number;
    sessionId: string;
    userId: string;
    now: string;
    freshAfter: string;
    stepUpAfter: string;
  },
): D1PreparedStatement {
  return env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, client_id, subject_id, outcome,
       metadata_json, occurred_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?
      WHERE ${managementCommitPredicate()}
        AND COALESCE((
          SELECT MAX(generation) FROM recovery_code_set WHERE user_id = ?
        ), 0) = ?
        AND (
          (? IS NULL AND NOT EXISTS (
            SELECT 1 FROM recovery_code_set
             WHERE user_id = ? AND revoked_at IS NULL
          ))
          OR EXISTS (
            SELECT 1 FROM recovery_code_set
             WHERE id = ? AND user_id = ? AND revoked_at IS NULL
          )
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
    ...managementCommitBindings(
      input.sessionId,
      input.userId,
      input.now,
      input.freshAfter,
      input.stepUpAfter,
    ),
    input.userId,
    input.maxGeneration,
    input.activeSetId,
    input.userId,
    input.activeSetId,
    input.userId,
  );
}

async function authenticatedManagement(
  c: Context<AppEnv>,
): Promise<
  | { ok: true; sessionId: string; userId: string; snapshot: ManagementSnapshot }
  | { ok: false; response: Response }
> {
  const disabled = recoveryDisabled(c);
  if (disabled) return { ok: false, response: disabled };
  const auth = createAuth(c.env, c.executionCtx);
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) {
    return { ok: false, response: c.json({ error: "unauthorized" }, 401) };
  }
  const snapshot = await loadManagementSnapshot(
    c.env,
    session.session.id,
    session.user.id,
  );
  if (!snapshot || snapshot.status !== "active") {
    return { ok: false, response: c.json({ error: "unauthorized" }, 401) };
  }
  return {
    ok: true,
    sessionId: session.session.id,
    userId: session.user.id,
    snapshot,
  };
}

export const recoveryCodeManagementRoutes = new Hono<AppEnv>();

recoveryCodeManagementRoutes.get("/api/account/recovery-codes", async (c) => {
  noStoreHeaders(c);
  const gate = await authenticatedManagement(c);
  if (!gate.ok) return gate.response;
  const active = gate.snapshot.active_set_id !== null;
  return c.json({
    configured: active,
    count: RECOVERY_CODE_COUNT,
    formatVersion: RECOVERY_FORMAT_VERSION,
    generation: gate.snapshot.active_set_generation,
    remaining: active ? gate.snapshot.active_set_remaining : 0,
    expiresAt: gate.snapshot.active_set_expires_at,
  });
});

recoveryCodeManagementRoutes.post("/api/account/recovery-codes/rotate", async (c) => {
  noStoreHeaders(c);
  const gate = await authenticatedManagement(c);
  if (!gate.ok) return gate.response;
  if (!isStrictRecoveryJsonMediaType(c.req.header("content-type") ?? null)) {
    return c.json({ error: "invalid_request" }, 415);
  }
  if (!(await isEmptyJsonObject(c.req.raw))) {
    return c.json({ error: "invalid_request" }, 400);
  }
  const config = readRuntimeConfig(c.env);
  const nowDate = new Date();
  const eligibility = mutationSnapshotEligible(
    gate.snapshot,
    nowDate.getTime(),
    config.passkeyStepUpMaxAgeMs,
  );
  if (eligibility) return c.json({ error: eligibility }, 403);

  const rateLimit = await c.env.AUTH_RATE_LIMITER.limit({ key: gate.userId });
  if (!rateLimit.success) return c.json({ error: "rate_limited" }, 429);

  const now = nowDate.toISOString();
  const freshAfter = new Date(
    nowDate.getTime() - FRESH_SESSION_MAX_AGE_MS,
  ).toISOString();
  const stepUpAfter = new Date(
    nowDate.getTime() - config.passkeyStepUpMaxAgeMs,
  ).toISOString();
  const generation = gate.snapshot.max_generation + 1;
  const setId = crypto.randomUUID();
  const generated = await generateRecoveryCodeSet();
  const event = createAuditEvent({
    eventType: "recovery.codes_issued",
    outcome: "success",
    actorUserId: gate.userId,
    subjectId: gate.userId,
    metadata: {
      count: RECOVERY_CODE_COUNT,
      formatVersion: RECOVERY_FORMAT_VERSION,
      generation,
      reason: gate.snapshot.active_set_id ? "rotate" : "initial",
    },
  });
  const statements: D1PreparedStatement[] = [
    managementAuditStatement(c.env, event, {
      activeSetId: gate.snapshot.active_set_id,
      maxGeneration: gate.snapshot.max_generation,
      sessionId: gate.sessionId,
      userId: gate.userId,
      now,
      freshAfter,
      stepUpAfter,
    }),
    c.env.PG72_ID_DB.prepare(
      `UPDATE recovery_code_set SET revoked_at = ?
        WHERE user_id = ? AND revoked_at IS NULL
          AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
    ).bind(now, gate.userId, event.eventId),
    c.env.PG72_ID_DB.prepare(
      `INSERT INTO recovery_code_set
        (id, user_id, generation, format_version, created_at, expires_at)
       SELECT ?, ?, ?, ?, ?, NULL
        WHERE EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
    ).bind(
      setId,
      gate.userId,
      generation,
      RECOVERY_FORMAT_VERSION,
      now,
      event.eventId,
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
        setId,
        index + 1,
        hash,
        setId,
        gate.userId,
        event.eventId,
      ),
    );
  });

  const results = await c.env.PG72_ID_DB.batch(statements);
  const complete =
    results[0]?.meta.changes === 1 &&
    results[2]?.meta.changes === 1 &&
    results.slice(3).every((result) => result.meta.changes === 1);
  if (!complete) return c.json({ error: "management_state_changed" }, 409);
  await enqueueSecurityEvent(c.env, event, c.executionCtx);
  return c.json({
    codes: generated.codes,
    count: RECOVERY_CODE_COUNT,
    expiresAt: null,
    formatVersion: RECOVERY_FORMAT_VERSION,
    generation,
  });
});

recoveryCodeManagementRoutes.delete("/api/account/recovery-codes", async (c) => {
  noStoreHeaders(c);
  const gate = await authenticatedManagement(c);
  if (!gate.ok) return gate.response;
  if (!gate.snapshot.active_set_id) {
    return c.json({ error: "recovery_codes_not_configured" }, 404);
  }
  const config = readRuntimeConfig(c.env);
  const nowDate = new Date();
  const eligibility = mutationSnapshotEligible(
    gate.snapshot,
    nowDate.getTime(),
    config.passkeyStepUpMaxAgeMs,
  );
  if (eligibility) return c.json({ error: eligibility }, 403);
  const rateLimit = await c.env.AUTH_RATE_LIMITER.limit({ key: gate.userId });
  if (!rateLimit.success) return c.json({ error: "rate_limited" }, 429);

  const now = nowDate.toISOString();
  const event = createAuditEvent({
    eventType: "recovery.codes_revoked",
    outcome: "success",
    actorUserId: gate.userId,
    subjectId: gate.userId,
    metadata: {
      formatVersion: RECOVERY_FORMAT_VERSION,
      generation: gate.snapshot.active_set_generation ?? 0,
      reason: "explicit",
    },
  });
  const results = await c.env.PG72_ID_DB.batch([
    managementAuditStatement(c.env, event, {
      activeSetId: gate.snapshot.active_set_id,
      maxGeneration: gate.snapshot.max_generation,
      sessionId: gate.sessionId,
      userId: gate.userId,
      now,
      freshAfter: new Date(
        nowDate.getTime() - FRESH_SESSION_MAX_AGE_MS,
      ).toISOString(),
      stepUpAfter: new Date(
        nowDate.getTime() - config.passkeyStepUpMaxAgeMs,
      ).toISOString(),
    }),
    c.env.PG72_ID_DB.prepare(
      `UPDATE recovery_code_set SET revoked_at = ?
        WHERE id = ? AND user_id = ? AND revoked_at IS NULL
          AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)
        RETURNING id`,
    ).bind(
      now,
      gate.snapshot.active_set_id,
      gate.userId,
      event.eventId,
    ),
  ]);
  if (results[0]?.meta.changes !== 1 || results[1]?.results.length !== 1) {
    return c.json({ error: "management_state_changed" }, 409);
  }
  await enqueueSecurityEvent(c.env, event, c.executionCtx);
  return c.json({ revoked: true });
});

export async function activeRecoveryCodeSet(
  env: Env,
  userId: string,
  now = new Date().toISOString(),
): Promise<RecoveryCodeSetRow | null> {
  return env.PG72_ID_DB.prepare(
    `SELECT active.id, active.generation, active.expires_at,
            COUNT(code.id) AS remaining
       FROM recovery_code_set AS active
       JOIN recovery_code AS code
         ON code.set_id = active.id AND code.consumed_at IS NULL
      WHERE active.user_id = ?
        AND active.revoked_at IS NULL
        AND (active.expires_at IS NULL OR active.expires_at > ?)
      GROUP BY active.id, active.generation, active.expires_at
      HAVING COUNT(code.id) > 0
      LIMIT 1`,
  )
    .bind(userId, now)
    .first<RecoveryCodeSetRow>();
}
