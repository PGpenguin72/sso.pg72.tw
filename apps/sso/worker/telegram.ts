import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import { makeSignature } from "better-auth/crypto";

import { recordAudit } from "./audit";
import { createAuth } from "./auth";
import {
  readAccountAccessState,
  recordRestrictedActionDenied,
} from "./account-access";
import { readRuntimeConfig, type RuntimeConfig } from "./config";
import { recordLoginAudit } from "./security-activity";

type AppEnv = { Bindings: Env };

/**
 * Telegram login (custom provider).
 *
 * Telegram is not an OAuth 2.0 / OIDC provider, so it cannot go through Better
 * Auth's `socialProviders`. Instead the browser renders the official Telegram
 * Login Widget, which returns a signed payload (id, first_name, ..., auth_date,
 * hash). This module verifies that payload server-side:
 *
 *   secret_key      = SHA-256(bot_token)
 *   data_check_str  = "\n".join(sorted "key=value" for every field except hash)
 *   expected_hash   = HMAC-SHA256(data_check_str, secret_key)   // hex
 *
 * and rejects stale payloads (auth_date freshness) to stop replay. The Telegram
 * numeric user id is the immutable identity (mapped to provider `telegram`,
 * accountId = telegram id); the display name is derived from the profile.
 *
 * Design decision — no email: Telegram never provides an email, so it cannot
 * satisfy PGID's verified-email enrollment boundary. A Telegram identity may
 * sign in only after it has been explicitly linked from an authenticated PGID
 * session. An unmatched identity is rate-limited, audited without PII, and
 * rejected in both invite and public registration modes; no placeholder account
 * is created.
 */

const TELEGRAM_PROVIDER_ID = "telegram";
/** Widget payloads older than this (seconds) are rejected as replays. */
const TELEGRAM_AUTH_MAX_AGE_SECONDS = 300;
/** Small allowance for clock skew when the payload is "from the future". */
const TELEGRAM_AUTH_FUTURE_SKEW_SECONDS = 60;
const SESSION_LIFETIME_MS = 60 * 60 * 24 * 30 * 1000;

export interface TelegramUser {
  id: string;
  firstName: string | null;
  lastName: string | null;
  username: string | null;
  photoUrl: string | null;
}

export type TelegramVerification =
  | { ok: true; user: TelegramUser }
  | { ok: false; error: string };

function toHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/** Constant-time comparison of two equal-purpose hex strings. */
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Verifies a Telegram Login Widget payload against the bot token and checks
 * freshness. Pure and side-effect free so it can be unit tested directly.
 */
export async function verifyTelegramAuth(
  data: Record<string, string>,
  botToken: string,
  nowMs: number,
): Promise<TelegramVerification> {
  const hash = data.hash;
  if (!hash || !/^[0-9a-f]{64}$/i.test(hash)) {
    return { ok: false, error: "invalid_telegram_auth" };
  }

  const dataCheckString = Object.keys(data)
    .filter((key) => key !== "hash")
    .sort()
    .map((key) => `${key}=${data[key]}`)
    .join("\n");

  const secretKey = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(botToken),
  );
  const key = await crypto.subtle.importKey(
    "raw",
    secretKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(dataCheckString),
  );
  if (!timingSafeEqualHex(toHex(signature), hash.toLowerCase())) {
    return { ok: false, error: "invalid_telegram_hash" };
  }

  const authDate = Number.parseInt(data.auth_date ?? "", 10);
  const nowSeconds = Math.floor(nowMs / 1000);
  if (
    !Number.isFinite(authDate) ||
    nowSeconds - authDate > TELEGRAM_AUTH_MAX_AGE_SECONDS ||
    authDate - nowSeconds > TELEGRAM_AUTH_FUTURE_SKEW_SECONDS
  ) {
    return { ok: false, error: "telegram_auth_expired" };
  }

  const id = data.id ?? "";
  if (!/^\d{1,20}$/.test(id)) {
    return { ok: false, error: "invalid_telegram_auth" };
  }

  return {
    ok: true,
    user: {
      id,
      firstName: data.first_name ?? null,
      lastName: data.last_name ?? null,
      username: data.username ?? null,
      photoUrl: data.photo_url ?? null,
    },
  };
}

/**
 * Mints a Better Auth-compatible session for the user and returns the cookie
 * strings to set. This mirrors the exact session-token shape Better Auth reads
 * (a `session` row plus a `<token>.<hmac>` signed cookie); it is the same
 * representation the test helpers construct.
 */
async function mintSessionCookies(
  env: Env,
  config: RuntimeConfig,
  userId: string,
  headers: Headers,
): Promise<string[]> {
  const sessionId = crypto.randomUUID();
  const token = crypto.randomUUID();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_LIFETIME_MS);

  await env.PG72_ID_DB.prepare(
    `INSERT INTO session
      (id, expiresAt, token, createdAt, updatedAt, ipAddress, userAgent, userId)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      sessionId,
      expiresAt.toISOString(),
      token,
      now.toISOString(),
      now.toISOString(),
      headers.get("cf-connecting-ip") ?? null,
      headers.get("user-agent") ?? null,
      userId,
    )
    .run();

  const signed = `${token}.${await makeSignature(token, env.BETTER_AUTH_SECRET)}`;
  const secure = config.environment !== "development";
  const cookieName = `${secure ? "__Secure-" : ""}pg72_id.session_token`;
  const attributes = [
    `${cookieName}=${signed}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.floor(SESSION_LIFETIME_MS / 1000)}`,
    ...(secure ? ["Secure"] : []),
  ];
  return [attributes.join("; ")];
}

async function readJson<T>(request: Request): Promise<T | null> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    return null;
  }
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
}

/** Coerces the widget payload into the string map the verifier expects. */
function toStringMap(input: unknown): Record<string, string> | null {
  if (typeof input !== "object" || input === null) return null;
  const map: Record<string, string> = {};
  for (const [key, value] of Object.entries(input)) {
    if (typeof value === "string") map[key] = value;
    else if (typeof value === "number") map[key] = String(value);
    else if (value === null || value === undefined) continue;
    else return null;
  }
  return map;
}

function telegramCookieResponse(
  body: Record<string, unknown>,
  status: 200,
  cookies: string[],
): Response {
  const headers = new Headers({ "Content-Type": "application/json" });
  for (const cookie of cookies) headers.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(body), { status, headers });
}

export const telegramRoutes = new Hono<AppEnv>();

// Public, unauthenticated config for the sign-in page's Telegram Login Widget.
// The widget needs the bot username to render; the flow is enabled only when a
// bot token is configured. No secret is exposed (the username is public, and
// appears in the widget itself).
telegramRoutes.get("/api/auth/telegram/config", (c) => {
  const enabled = Boolean(c.env.TELEGRAM_BOT_TOKEN);
  const botUsername = c.env.TELEGRAM_BOT_USERNAME?.trim() || null;
  return c.json(
    { enabled: enabled && botUsername !== null, botUsername },
    200,
    { "Cache-Control": "no-store" },
  );
});

for (const path of ["/api/auth/telegram", "/api/auth/telegram/link"]) {
  telegramRoutes.use(
    path,
    bodyLimit({
      maxSize: 4 * 1024,
      onError: (c) => c.json({ error: "request_too_large" }, 413),
    }),
  );
  telegramRoutes.use(path, async (c, next) => {
    const config = readRuntimeConfig(c.env);
    if (c.req.header("origin") !== config.authBaseUrl) {
      return c.json({ error: "invalid_origin" }, 403);
    }
    // The provider is optional: without a configured bot token it is disabled
    // and never affects Google/Passkey.
    if (!c.env.TELEGRAM_BOT_TOKEN) {
      return c.json({ error: "telegram_disabled" }, 404);
    }
    const ip = c.req.header("cf-connecting-ip") ?? "local";
    const rateLimit = await c.env.AUTH_RATE_LIMITER.limit({ key: `tg:${ip}` });
    if (!rateLimit.success) {
      return c.json({ error: "rate_limited" }, 429);
    }
    await next();
  });
}

async function verifiedTelegramUser(
  c: Context<AppEnv>,
): Promise<TelegramUser | Response> {
  const payload = await readJson<Record<string, unknown>>(c.req.raw);
  const data = payload ? toStringMap(payload) : null;
  if (!data) {
    return c.json({ error: "invalid_telegram_auth" }, 400);
  }
  const verification = await verifyTelegramAuth(
    data,
    c.env.TELEGRAM_BOT_TOKEN as string,
    Date.now(),
  );
  if (!verification.ok) {
    return c.json({ error: verification.error }, 400);
  }
  return verification.user;
}

/**
 * Login / sign-up via the Telegram Login Widget. No session is required: an
 * existing Telegram-linked account signs in. Telegram does not provide a
 * verified email, so an unmatched identity cannot create a PGID account in
 * either registration mode.
 */
telegramRoutes.post("/api/auth/telegram", async (c) => {
  const verified = await verifiedTelegramUser(c);
  if (verified instanceof Response) return verified;
  const config = readRuntimeConfig(c.env);

  const existing = await c.env.PG72_ID_DB.prepare(
    `SELECT userId FROM account WHERE providerId = ? AND accountId = ? LIMIT 1`,
  )
    .bind(TELEGRAM_PROVIDER_ID, verified.id)
    .first<{ userId: string }>();

  if (existing) {
    const user = await c.env.PG72_ID_DB.prepare(
      "SELECT id, status FROM user WHERE id = ? LIMIT 1",
    )
      .bind(existing.userId)
      .first<{ id: string; status: string }>();
    if (!user || user.status !== "active") {
      return c.json({ error: "account_unavailable" }, 403);
    }
    const cookies = await mintSessionCookies(
      c.env,
      config,
      user.id,
      c.req.raw.headers,
    );
    await recordLoginAudit(
      c.env,
      user.id,
      { path: "/callback/telegram", request: { headers: c.req.raw.headers } },
      c.executionCtx,
    );
    return telegramCookieResponse({ signedIn: true }, 200, cookies);
  }

  // Unmatched Telegram identities cannot satisfy the verified-email enrollment
  // boundary. Consume the dedicated registration budget before writing the
  // denial audit so this unauthenticated path cannot amplify D1 writes.
  const registrationLimit = await c.env.REGISTRATION_RATE_LIMITER.limit({
    key: c.req.header("cf-connecting-ip") ?? "local",
  });
  if (!registrationLimit.success) {
    await recordAudit(
      c.env,
      { eventType: "registration.rate_limited", outcome: "denied" },
      c.executionCtx,
    );
    return c.json({ error: "rate_limited" }, 429);
  }

  await recordAudit(
    c.env,
    {
      eventType: "registration.denied",
      outcome: "denied",
      metadata: {
        provider: TELEGRAM_PROVIDER_ID,
        reason: "verified_email_required",
      },
    },
    c.executionCtx,
  );
  return c.json({ error: "registration_closed" }, 403);
});

/**
 * Explicit Telegram linking for an already signed-in user. This is the only
 * way a Telegram identity attaches to an existing account (no implicit
 * linking); the Telegram id must not already belong to another user.
 */
telegramRoutes.post("/api/auth/telegram/link", async (c) => {
  const auth = createAuth(c.env, c.executionCtx);
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) {
    return c.json({ error: "unauthorized" }, 401);
  }
  const access = await readAccountAccessState(c.env, session.user.id);
  if (!access || access.status !== "active") {
    return c.json({ error: "unauthorized" }, 401);
  }
  if (access.accessLevel === "restricted") {
    try {
      await recordRestrictedActionDenied(
        c.env,
        session.user.id,
        "provider_link",
        c.executionCtx,
      );
    } catch (error) {
      console.error(
        JSON.stringify({
          event: "restricted_action_audit_failed",
          error: error instanceof Error ? error.name : "UnknownError",
        }),
      );
    }
    return c.json({ error: "forbidden" }, 403);
  }

  const verified = await verifiedTelegramUser(c);
  if (verified instanceof Response) return verified;

  const now = new Date().toISOString();
  const inserted = await c.env.PG72_ID_DB.prepare(
    `INSERT OR IGNORE INTO account
      (id, accountId, providerId, userId, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      crypto.randomUUID(),
      verified.id,
      TELEGRAM_PROVIDER_ID,
      session.user.id,
      now,
      now,
    )
    .run();

  if (inserted.meta.changes !== 1) {
    const owner = await c.env.PG72_ID_DB.prepare(
      `SELECT userId FROM account WHERE providerId = ? AND accountId = ? LIMIT 1`,
    )
      .bind(TELEGRAM_PROVIDER_ID, verified.id)
      .first<{ userId: string }>();
    if (owner?.userId === session.user.id) {
      return c.json({ error: "already_linked" }, 409);
    }
    // Fail closed if another owner won the insert, or if an unexpected ignored
    // constraint leaves no visible owner. Do not infer conflicts from error text.
    return c.json({ error: "telegram_already_linked" }, 409);
  }

  await recordAudit(
    c.env,
    {
      eventType: "account.linked",
      outcome: "success",
      subjectId: session.user.id,
      metadata: { provider: TELEGRAM_PROVIDER_ID },
    },
    c.executionCtx,
  );

  return c.json({ linked: true, provider: TELEGRAM_PROVIDER_ID });
});
