import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";

import { recordAudit } from "./audit";
import { createAuth } from "./auth";
import { readRuntimeConfig } from "./config";

type AppEnv = { Bindings: Env };

export const DISPLAY_NAME_MAX_LENGTH = 64;
const DISPLAY_NAME_MAX_INPUT_LENGTH = 1024;
/** Versioned so a future avatar style can change URLs without cache poisoning. */
const GENERATED_AVATAR_PATH_PREFIX = "/api/avatar/v1/";
const AVATAR_GRID = 5;

/**
 * Control (Cc) and format (Cf) characters are stripped before validation:
 * they cover C0/C1 controls, zero-width characters, and bidi override
 * characters that could spoof names in the consent screen or in RP UIs.
 */
const DISALLOWED_NAME_CHARS = /[\p{Cc}\p{Cf}]/gu;

interface ProfileInput {
  name?: unknown;
  avatar?: unknown;
}

interface UserImageRow {
  name: string;
  image: string | null;
  googleImage: string | null;
}

export type AvatarSource = "google" | "generated";

export function normalizeDisplayName(value: unknown): string | null {
  if (typeof value !== "string" || value.length > DISPLAY_NAME_MAX_INPUT_LENGTH) {
    return null;
  }
  const normalized = value.replace(DISALLOWED_NAME_CHARS, "").trim();
  if (normalized.length === 0 || normalized.length > DISPLAY_NAME_MAX_LENGTH) {
    return null;
  }
  return normalized;
}

export function generatedAvatarUrl(authBaseUrl: string, userId: string): string {
  return `${authBaseUrl}${GENERATED_AVATAR_PATH_PREFIX}${userId}.svg`;
}

export function isGeneratedAvatarUrl(
  value: string | null,
  authBaseUrl: string,
): boolean {
  if (!value) return false;
  try {
    const url = new URL(value);
    return (
      url.origin === authBaseUrl &&
      url.pathname.startsWith(GENERATED_AVATAR_PATH_PREFIX)
    );
  } catch {
    return false;
  }
}

/**
 * Deterministic identicon rendered from a SHA-256 of the user id. It reads
 * nothing from the database, embeds no user-controlled content, and is served
 * from the SSO origin, so `img-src 'self'` keeps covering every avatar.
 */
export async function renderIdenticonSvg(seed: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(seed.toLowerCase()),
  );
  const bytes = new Uint8Array(digest);
  const hue = (((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0)) % 360;
  const background = `hsl(${hue} 45% 91%)`;
  const foreground = `hsl(${hue} 55% 40%)`;

  const cells: string[] = [];
  for (let row = 0; row < AVATAR_GRID; row += 1) {
    for (let column = 0; column < 3; column += 1) {
      const bitIndex = row * 3 + column;
      const byte = bytes[2 + (bitIndex >> 3)] ?? 0;
      if (((byte >> (bitIndex & 7)) & 1) === 0) continue;
      cells.push(`<rect x="${column + 1}" y="${row + 1}" width="1" height="1"/>`);
      const mirrored = AVATAR_GRID - 1 - column;
      if (mirrored !== column) {
        cells.push(`<rect x="${mirrored + 1}" y="${row + 1}" width="1" height="1"/>`);
      }
    }
  }

  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 7 7" width="112" height="112" role="img" aria-label="PGID avatar">` +
    `<rect width="7" height="7" fill="${background}"/>` +
    `<g fill="${foreground}">${cells.join("")}</g>` +
    `</svg>`
  );
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  );
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

type UserGate =
  | { ok: true; userId: string }
  | { ok: false; response: Response };

async function requireActiveUser(
  c: Context<AppEnv>,
  { rateLimited }: { rateLimited: boolean },
): Promise<UserGate> {
  const auth = createAuth(c.env, c.executionCtx);
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session || session.user.status !== "active") {
    return { ok: false, response: c.json({ error: "unauthorized" }, 401) };
  }

  if (rateLimited) {
    const rateLimit = await c.env.AUTH_RATE_LIMITER.limit({
      key: session.user.id,
    });
    if (!rateLimit.success) {
      return { ok: false, response: c.json({ error: "rate_limited" }, 429) };
    }
  }

  return { ok: true, userId: session.user.id };
}

async function auditAccountEvent(
  c: Context<AppEnv>,
  eventType: string,
  outcome: "success" | "denied",
  subjectId: string,
): Promise<void> {
  try {
    await recordAudit(c.env, { eventType, outcome, subjectId }, c.executionCtx);
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "account_audit_failed",
        eventType,
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
  }
}

export const accountRoutes = new Hono<AppEnv>();

const PROTECTED_ACCOUNT_PATHS = ["/api/account/profile"];

for (const path of PROTECTED_ACCOUNT_PATHS) {
  accountRoutes.use(
    path,
    bodyLimit({
      maxSize: 4 * 1024,
      onError: (c) => c.json({ error: "request_too_large" }, 413),
    }),
  );
  accountRoutes.use(path, async (c, next) => {
    const config = readRuntimeConfig(c.env);
    const origin = c.req.header("origin");
    // Browsers omit Origin on same-origin GET fetches, so read-only requests
    // only need to match when the header is present. Mutations always require
    // the exact first-party origin.
    const isReadOnly = c.req.method === "GET" || c.req.method === "HEAD";
    if (
      isReadOnly
        ? origin !== undefined && origin !== config.authBaseUrl
        : origin !== config.authBaseUrl
    ) {
      return c.json({ error: "invalid_origin" }, 403);
    }
    await next();
  });
}

accountRoutes.get("/api/account/profile", async (c) => {
  const gate = await requireActiveUser(c, { rateLimited: false });
  if (!gate.ok) return gate.response;

  const config = readRuntimeConfig(c.env);
  const row = await c.env.PG72_ID_DB.prepare(
    "SELECT name, image, googleImage FROM user WHERE id = ? LIMIT 1",
  )
    .bind(gate.userId)
    .first<UserImageRow>();
  if (!row) {
    return c.json({ error: "unauthorized" }, 401);
  }

  const usingGenerated = isGeneratedAvatarUrl(row.image, config.authBaseUrl);
  return c.json({
    name: row.name,
    image: row.image,
    avatarSource: (usingGenerated ? "generated" : "google") satisfies AvatarSource,
    generatedAvatarUrl: generatedAvatarUrl(config.authBaseUrl, gate.userId),
    googleAvatarUrl: usingGenerated ? row.googleImage : row.image,
  });
});

accountRoutes.post("/api/account/profile", async (c) => {
  const gate = await requireActiveUser(c, { rateLimited: true });
  if (!gate.ok) return gate.response;

  const input = await readJson<ProfileInput>(c.req.raw);
  if (!input || (input.name === undefined && input.avatar === undefined)) {
    return c.json({ error: "invalid_request" }, 400);
  }

  let name: string | null = null;
  if (input.name !== undefined) {
    name = normalizeDisplayName(input.name);
    if (!name) {
      return c.json({ error: "invalid_name" }, 400);
    }
  }
  if (
    input.avatar !== undefined &&
    input.avatar !== "google" &&
    input.avatar !== "generated"
  ) {
    return c.json({ error: "invalid_avatar" }, 400);
  }

  const config = readRuntimeConfig(c.env);
  const row = await c.env.PG72_ID_DB.prepare(
    "SELECT name, image, googleImage FROM user WHERE id = ? LIMIT 1",
  )
    .bind(gate.userId)
    .first<UserImageRow>();
  if (!row) {
    return c.json({ error: "unauthorized" }, 401);
  }

  let image = row.image;
  let googleImage = row.googleImage;
  if (input.avatar === "generated") {
    if (!isGeneratedAvatarUrl(row.image, config.authBaseUrl)) {
      googleImage = row.image ?? row.googleImage;
    }
    image = generatedAvatarUrl(config.authBaseUrl, gate.userId);
  } else if (input.avatar === "google") {
    if (isGeneratedAvatarUrl(row.image, config.authBaseUrl)) {
      image = row.googleImage;
    }
  }

  await c.env.PG72_ID_DB.prepare(
    "UPDATE user SET name = ?, image = ?, googleImage = ?, updatedAt = ? WHERE id = ?",
  )
    .bind(name ?? row.name, image, googleImage, new Date().toISOString(), gate.userId)
    .run();

  // Only the event itself is recorded; neither old nor new values are logged.
  await auditAccountEvent(c, "user.profile_updated", "success", gate.userId);

  return c.json({
    name: name ?? row.name,
    image,
    avatarSource: (isGeneratedAvatarUrl(image, config.authBaseUrl)
      ? "generated"
      : "google") satisfies AvatarSource,
  });
});

accountRoutes.get("/api/avatar/v1/:file", async (c) => {
  const file = c.req.param("file");
  const userId = file.endsWith(".svg") ? file.slice(0, -4) : file;
  if (!isUuid(userId)) {
    return c.json({ error: "not_found" }, 404);
  }

  const svg = await renderIdenticonSvg(userId);
  return c.body(svg, 200, {
    "Content-Type": "image/svg+xml; charset=utf-8",
    // Deterministic output: safe to cache aggressively.
    "Cache-Control": "public, max-age=86400, immutable",
  });
});
