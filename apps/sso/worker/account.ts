import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";

import {
  readAccountAccessState,
  type AccountAccessLevel,
} from "./account-access";
import {
  base64ToBytes,
  bytesToBase64,
  decodeDataUrl,
  validateAvatarBytes,
} from "./avatar";
import { recordAudit } from "./audit";
import { createAuth } from "./auth";
import { readRuntimeConfig } from "./config";
import { activeRecoveryCodeSet } from "./recovery-codes";
import {
  decodeActivityCursor,
  encodeActivityCursor,
  providerFromMetadata,
  summaryForEvent,
  SELF_ACTIVITY_EVENT_TYPES,
} from "./security-activity";

type AppEnv = { Bindings: Env };

export const DISPLAY_NAME_MAX_LENGTH = 64;
const DISPLAY_NAME_MAX_INPUT_LENGTH = 1024;
/** Versioned so a future avatar style can change URLs without cache poisoning. */
const GENERATED_AVATAR_PATH_PREFIX = "/api/avatar/v1/";
/** Path prefix for a user's self-hosted uploaded avatar (`.../<avatarId>`). */
const UPLOADED_AVATAR_PATH_PREFIX = "/api/account/avatar/";
const AVATAR_GRID = 5;
const SECURITY_ACTIVITY_PAGE_SIZE = 25;

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

interface AccountRow {
  id: string;
  providerId: string;
  createdAt: string;
}

interface AccountOwnershipRow {
  id: string;
  providerId: string;
}

interface LoginMethodCountRow {
  accounts: number;
  passkeys: number;
}

export type AvatarSource = "google" | "generated" | "upload";

/** Request body of `POST /api/account/avatar/mode`. */
type AvatarMode = "google" | "identicon" | "upload";

/**
 * Providers a signed-in user may explicitly link. Adding a future provider
 * means registering it here and in the Better Auth `socialProviders` config;
 * the listing/unlink policy below is provider-agnostic.
 */
export const LINKABLE_PROVIDERS: readonly string[] = ["google"];

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

export function uploadedAvatarUrl(authBaseUrl: string, avatarId: string): string {
  return `${authBaseUrl}${UPLOADED_AVATAR_PATH_PREFIX}${avatarId}`;
}

export function isUploadedAvatarUrl(
  value: string | null,
  authBaseUrl: string,
): boolean {
  if (!value) return false;
  try {
    const url = new URL(value);
    if (url.origin !== authBaseUrl || !url.pathname.startsWith(UPLOADED_AVATAR_PATH_PREFIX)) {
      return false;
    }
    return isUuid(url.pathname.slice(UPLOADED_AVATAR_PATH_PREFIX.length));
  } catch {
    return false;
  }
}

/** Three-way avatar source classification for a stored `user.image` URL. */
export function avatarSourceOf(
  image: string | null,
  authBaseUrl: string,
): AvatarSource {
  if (isGeneratedAvatarUrl(image, authBaseUrl)) return "generated";
  if (isUploadedAvatarUrl(image, authBaseUrl)) return "upload";
  return "google";
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
  | { ok: true; accessLevel: AccountAccessLevel; userId: string }
  | { ok: false; response: Response };

async function requireActiveUser(
  c: Context<AppEnv>,
  { rateLimited }: { rateLimited: boolean },
): Promise<UserGate> {
  const auth = createAuth(c.env, c.executionCtx);
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) {
    return { ok: false, response: c.json({ error: "unauthorized" }, 401) };
  }
  const access = await readAccountAccessState(c.env, session.user.id);
  if (!access || access.status !== "active") {
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

  return {
    ok: true,
    accessLevel: access.accessLevel,
    userId: session.user.id,
  };
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

async function loginMethodCounts(
  env: Env,
  userId: string,
): Promise<LoginMethodCountRow> {
  const counts = await env.PG72_ID_DB.prepare(
    `SELECT
      (SELECT COUNT(*) FROM account WHERE userId = ?) AS accounts,
      (SELECT COUNT(*) FROM passkey WHERE userId = ?) AS passkeys`,
  )
    .bind(userId, userId)
    .first<LoginMethodCountRow>();
  return { accounts: counts?.accounts ?? 0, passkeys: counts?.passkeys ?? 0 };
}

export const accountRoutes = new Hono<AppEnv>();

const PROTECTED_ACCOUNT_PATHS = [
  "/api/account/profile",
  "/api/account/login-methods",
  "/api/account/login-methods/:accountId",
];

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

/** Exact first-party Origin guard for avatar mutations (never a public GET). */
async function requireFirstPartyOrigin(
  c: Context<AppEnv>,
  next: () => Promise<void>,
): Promise<Response | void> {
  const config = readRuntimeConfig(c.env);
  if (c.req.header("origin") !== config.authBaseUrl) {
    return c.json({ error: "invalid_origin" }, 403);
  }
  await next();
}

// The upload endpoint carries an image body, so it gets a dedicated 512KB
// limit (headroom above MAX_AVATAR_BYTES for multipart/data-URL overhead)
// rather than the 4KB JSON limit above.
accountRoutes.use(
  "/api/account/avatar",
  bodyLimit({
    maxSize: 512 * 1024,
    onError: (c) => c.json({ error: "request_too_large" }, 413),
  }),
);
accountRoutes.use("/api/account/avatar", requireFirstPartyOrigin);
accountRoutes.use(
  "/api/account/avatar/mode",
  bodyLimit({
    maxSize: 4 * 1024,
    onError: (c) => c.json({ error: "request_too_large" }, 413),
  }),
);
accountRoutes.use("/api/account/avatar/mode", requireFirstPartyOrigin);

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

  const source = avatarSourceOf(row.image, config.authBaseUrl);
  return c.json({
    name: row.name,
    image: row.image,
    avatarSource: source,
    generatedAvatarUrl: generatedAvatarUrl(config.authBaseUrl, gate.userId),
    googleAvatarUrl: source === "google" ? row.image : row.googleImage,
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
  const currentSource = avatarSourceOf(row.image, config.authBaseUrl);
  if (input.avatar === "generated") {
    // Preserve the Google picture only when leaving the Google source; never
    // overwrite it with a generated or uploaded URL.
    if (currentSource === "google") {
      googleImage = row.image ?? row.googleImage;
    }
    image = generatedAvatarUrl(config.authBaseUrl, gate.userId);
  } else if (input.avatar === "google") {
    if (currentSource !== "google") {
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
    avatarSource: avatarSourceOf(image, config.authBaseUrl),
  });
});

accountRoutes.get("/api/account/login-methods", async (c) => {
  const gate = await requireActiveUser(c, { rateLimited: false });
  if (!gate.ok) return gate.response;

  const accounts = await c.env.PG72_ID_DB.prepare(
    `SELECT id, providerId, createdAt
       FROM account
      WHERE userId = ?
      ORDER BY createdAt ASC, id ASC`,
  )
    .bind(gate.userId)
    .all<AccountRow>();
  const counts = await loginMethodCounts(c.env, gate.userId);
  const totalMethods = counts.accounts + counts.passkeys;
  const recoveryEnabled = readRuntimeConfig(c.env).recoveryEnabled;
  const recoveryCodes =
    recoveryEnabled && counts.accounts === 1
      ? await activeRecoveryCodeSet(c.env, gate.userId)
      : null;
  const linkedProviders = new Set(
    accounts.results.map((account) => account.providerId),
  );

  return c.json({
    accessLevel: gate.accessLevel,
    providers: accounts.results.map((account) => ({
      id: account.id,
      provider: account.providerId,
      createdAt: account.createdAt,
      canUnlink:
        totalMethods > 1 &&
        (counts.accounts > 1 || (recoveryCodes?.remaining ?? 0) > 0),
      recoveryCodeRequired:
        counts.accounts === 1 &&
        counts.passkeys > 0 &&
        recoveryEnabled &&
        (recoveryCodes?.remaining ?? 0) === 0,
      recoveryUnavailable:
        counts.accounts === 1 && counts.passkeys > 0 && !recoveryEnabled,
    })),
    passkeyCount: counts.passkeys,
    linkable:
      gate.accessLevel === "standard"
        ? LINKABLE_PROVIDERS.filter(
            (provider) => !linkedProviders.has(provider),
          )
        : [],
  });
});

accountRoutes.delete("/api/account/login-methods/:accountId", async (c) => {
  const gate = await requireActiveUser(c, { rateLimited: true });
  if (!gate.ok) return gate.response;

  const accountId = c.req.param("accountId");
  if (!isUuid(accountId)) {
    return c.json({ error: "invalid_account" }, 400);
  }

  const account = await c.env.PG72_ID_DB.prepare(
    "SELECT id, providerId FROM account WHERE id = ? AND userId = ? LIMIT 1",
  )
    .bind(accountId, gate.userId)
    .first<AccountOwnershipRow>();
  if (!account) {
    return c.json({ error: "account_not_found" }, 404);
  }

  // The final social account requires both another sign-in method and an
  // active, unused recovery code. The committing DELETE repeats these guards.
  const counts = await loginMethodCounts(c.env, gate.userId);
  if (counts.accounts + counts.passkeys <= 1) {
    await auditAccountEvent(c, "account.unlink_blocked", "denied", gate.userId);
    return c.json({ error: "last_login_method" }, 409);
  }

  const recoveryEnabled = readRuntimeConfig(c.env).recoveryEnabled;
  const now = new Date().toISOString();
  if (
    counts.accounts === 1 &&
    (!recoveryEnabled ||
      !(await activeRecoveryCodeSet(c.env, gate.userId, now)))
  ) {
    await auditAccountEvent(c, "account.unlink_blocked", "denied", gate.userId);
    return c.json({ error: "recovery_code_required" }, 409);
  }

  const deletion = await c.env.PG72_ID_DB.prepare(
    `DELETE FROM account
      WHERE id = ? AND userId = ?
        AND (
          (SELECT COUNT(*) FROM account WHERE userId = ?) > 1
          OR (? = 1 AND EXISTS (
            SELECT 1
              FROM recovery_code_set
              JOIN recovery_code
                ON recovery_code.set_id = recovery_code_set.id
             WHERE recovery_code_set.user_id = ?
               AND recovery_code_set.revoked_at IS NULL
               AND (
                 recovery_code_set.expires_at IS NULL
                 OR recovery_code_set.expires_at > ?
               )
               AND recovery_code.consumed_at IS NULL
          ))
        )
        AND (
          (SELECT COUNT(*) FROM account WHERE userId = ?)
          + (SELECT COUNT(*) FROM passkey WHERE userId = ?)
        ) > 1`,
  )
    .bind(
      accountId,
      gate.userId,
      gate.userId,
      recoveryEnabled ? 1 : 0,
      gate.userId,
      now,
      gate.userId,
      gate.userId,
    )
    .run();
  if (deletion.meta.changes !== 1) {
    const stillOwned = await c.env.PG72_ID_DB.prepare(
      "SELECT 1 AS present FROM account WHERE id = ? AND userId = ?",
    )
      .bind(accountId, gate.userId)
      .first();
    if (stillOwned) {
      const refreshedCounts = await loginMethodCounts(c.env, gate.userId);
      await auditAccountEvent(
        c,
        "account.unlink_blocked",
        "denied",
        gate.userId,
      );
      return c.json(
        {
          error:
            refreshedCounts.accounts + refreshedCounts.passkeys <= 1
              ? "last_login_method"
              : "recovery_code_required",
        },
        409,
      );
    }
    return c.json({ error: "account_not_found" }, 404);
  }

  await auditAccountEvent(c, "account.unlinked", "success", gate.userId);

  return c.json({ unlinked: true, provider: account.providerId });
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

/** Reads the raw image bytes from a multipart file part or a JSON data URL. */
async function readAvatarUpload(request: Request): Promise<Uint8Array | null> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (contentType.startsWith("multipart/form-data")) {
    const form = await request.formData();
    const file = form.get("file") ?? form.get("avatar");
    if (file instanceof File) {
      return new Uint8Array(await file.arrayBuffer());
    }
    return null;
  }
  if (contentType.startsWith("application/json")) {
    const body = (await request.json()) as { dataUrl?: unknown };
    const decoded = decodeDataUrl(body?.dataUrl);
    return decoded ? decoded.bytes : null;
  }
  return null;
}

accountRoutes.post("/api/account/avatar", async (c) => {
  const gate = await requireActiveUser(c, { rateLimited: true });
  if (!gate.ok) return gate.response;

  let bytes: Uint8Array | null;
  try {
    bytes = await readAvatarUpload(c.req.raw);
  } catch {
    return c.json({ error: "invalid_request" }, 400);
  }
  if (!bytes) {
    return c.json({ error: "invalid_request" }, 400);
  }

  // The content type is always re-derived from the signature bytes here; the
  // client-supplied MIME (multipart or data URL) is never trusted.
  const validation = validateAvatarBytes(bytes);
  if (!validation.ok) {
    return c.json({ error: validation.error }, 400);
  }

  const config = readRuntimeConfig(c.env);
  const row = await c.env.PG72_ID_DB.prepare(
    "SELECT image, googleImage FROM user WHERE id = ? LIMIT 1",
  )
    .bind(gate.userId)
    .first<UserImageRow>();
  if (!row) {
    return c.json({ error: "unauthorized" }, 401);
  }

  const avatarId = crypto.randomUUID();
  const now = new Date().toISOString();
  const imageUrl = uploadedAvatarUrl(config.authBaseUrl, avatarId);
  // Preserve the Google picture the first time we leave the Google source.
  const googleImage =
    avatarSourceOf(row.image, config.authBaseUrl) === "google"
      ? (row.image ?? row.googleImage)
      : row.googleImage;

  // Only the current avatar is retained: drop any previous row, insert the new
  // bytes, and point user.image (the OIDC `picture` claim) at the fresh id.
  await c.env.PG72_ID_DB.batch([
    c.env.PG72_ID_DB.prepare("DELETE FROM user_avatar WHERE user_id = ?").bind(
      gate.userId,
    ),
    c.env.PG72_ID_DB.prepare(
      `INSERT INTO user_avatar
        (id, user_id, content_type, data, byte_size, width, height, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      avatarId,
      gate.userId,
      validation.contentType,
      bytesToBase64(bytes),
      bytes.length,
      validation.width,
      validation.height,
      now,
    ),
    c.env.PG72_ID_DB.prepare(
      "UPDATE user SET image = ?, googleImage = ?, updatedAt = ? WHERE id = ?",
    ).bind(imageUrl, googleImage, now, gate.userId),
  ]);

  await auditAccountEvent(c, "user.avatar_updated", "success", gate.userId);

  return c.json({ imageUrl, avatarSource: "upload" satisfies AvatarSource });
});

accountRoutes.post("/api/account/avatar/mode", async (c) => {
  const gate = await requireActiveUser(c, { rateLimited: true });
  if (!gate.ok) return gate.response;

  const input = await readJson<{ mode?: unknown }>(c.req.raw);
  const mode = input?.mode;
  if (mode !== "google" && mode !== "identicon" && mode !== "upload") {
    return c.json({ error: "invalid_mode" }, 400);
  }

  const config = readRuntimeConfig(c.env);
  const row = await c.env.PG72_ID_DB.prepare(
    "SELECT image, googleImage FROM user WHERE id = ? LIMIT 1",
  )
    .bind(gate.userId)
    .first<UserImageRow>();
  if (!row) {
    return c.json({ error: "unauthorized" }, 401);
  }

  const currentSource = avatarSourceOf(row.image, config.authBaseUrl);
  let googleImage = row.googleImage;
  if (currentSource === "google" && mode !== "google") {
    googleImage = row.image ?? row.googleImage;
  }

  let image: string | null;
  let source: AvatarSource;
  if (mode === "identicon") {
    image = generatedAvatarUrl(config.authBaseUrl, gate.userId);
    source = "generated";
  } else if (mode === "upload") {
    const avatar = await c.env.PG72_ID_DB.prepare(
      `SELECT id FROM user_avatar
        WHERE user_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1`,
    )
      .bind(gate.userId)
      .first<{ id: string }>();
    if (!avatar) {
      return c.json({ error: "no_avatar" }, 409);
    }
    image = uploadedAvatarUrl(config.authBaseUrl, avatar.id);
    source = "upload";
  } else {
    image = googleImage;
    source = "google";
  }

  const now = new Date().toISOString();
  await c.env.PG72_ID_DB.prepare(
    "UPDATE user SET image = ?, googleImage = ?, updatedAt = ? WHERE id = ?",
  )
    .bind(image, googleImage, now, gate.userId)
    .run();

  await auditAccountEvent(c, "user.avatar_updated", "success", gate.userId);

  return c.json({ imageUrl: image, avatarSource: source });
});

accountRoutes.get("/api/account/avatar/:id", async (c) => {
  const id = c.req.param("id");
  if (!isUuid(id)) {
    return c.json({ error: "not_found" }, 404);
  }

  const row = await c.env.PG72_ID_DB.prepare(
    "SELECT content_type, data FROM user_avatar WHERE id = ? LIMIT 1",
  )
    .bind(id)
    .first<{ content_type: string; data: string }>();
  if (!row) {
    return c.json({ error: "not_found" }, 404);
  }

  return new Response(base64ToBytes(row.data), {
    status: 200,
    headers: {
      "Content-Type": row.content_type,
      // A new upload always mints a new id, so a given id is immutable.
      "Cache-Control": "public, max-age=86400, immutable",
    },
  });
});

accountRoutes.get("/api/account/security-activity", async (c) => {
  const gate = await requireActiveUser(c, { rateLimited: false });
  if (!gate.ok) return gate.response;

  const cursorParam = c.req.query("cursor");
  let cursor: { occurredAt: string; id: string } | null = null;
  if (cursorParam !== undefined) {
    cursor = decodeActivityCursor(cursorParam);
    if (!cursor) {
      return c.json({ error: "invalid_cursor" }, 400);
    }
  }

  const placeholders = SELF_ACTIVITY_EVENT_TYPES.map(() => "?").join(", ");
  const bindings: (string | number)[] = [
    gate.userId,
    ...SELF_ACTIVITY_EVENT_TYPES,
  ];
  let cursorClause = "";
  if (cursor) {
    cursorClause =
      "AND (occurred_at < ? OR (occurred_at = ? AND id < ?))";
    bindings.push(cursor.occurredAt, cursor.occurredAt, cursor.id);
  }
  bindings.push(SECURITY_ACTIVITY_PAGE_SIZE + 1);

  const result = await c.env.PG72_ID_DB.prepare(
    `SELECT id, event_type, occurred_at, metadata_json
       FROM audit_event
      WHERE subject_id = ?
        AND event_type IN (${placeholders})
        ${cursorClause}
      ORDER BY occurred_at DESC, id DESC
      LIMIT ?`,
  )
    .bind(...bindings)
    .all<{
      id: string;
      event_type: string;
      occurred_at: string;
      metadata_json: string | null;
    }>();

  const rows = result.results;
  const hasMore = rows.length > SECURITY_ACTIVITY_PAGE_SIZE;
  const page = hasMore ? rows.slice(0, SECURITY_ACTIVITY_PAGE_SIZE) : rows;
  const last = page.at(-1);

  return c.json({
    events: page.map((row) => {
      const provider = providerFromMetadata(row.metadata_json);
      return {
        id: row.id,
        type: row.event_type,
        at: row.occurred_at,
        summary: summaryForEvent(row.event_type),
        ...(provider ? { provider } : {}),
      };
    }),
    ...(hasMore && last
      ? { nextCursor: encodeActivityCursor(last.occurred_at, last.id) }
      : {}),
  });
});
