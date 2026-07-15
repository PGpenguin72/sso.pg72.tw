import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";

import { accountRoutes } from "./account";
import { adminClientRoutes } from "./admin-clients";
import { requireAdminPermission } from "./admin-gate";
import {
  adminUserRoutes,
  applyRoleChange,
  deniedRoleChange,
  fetchTarget,
} from "./admin-users";
import {
  consumeSecurityEvents,
  recordAudit,
  type SecurityEvent,
} from "./audit";
import { createAuth } from "./auth";
import {
  developerNameFromMetadata,
  parseClientMetadataRecord,
  redirectHostsFromUris,
  trustUrlOrNull,
} from "./client-metadata";
import { normalizeEmail, readRuntimeConfig } from "./config";
import {
  adminOauthReportRoutes,
  oauthReportRoutes,
} from "./oauth-reports";
import { ASSIGNABLE_ROLES, isPlatformRole } from "./roles";
import {
  ACTIVITY_AUDIT_PATHS,
  parseConsentActivity,
  recordAuthPathActivity,
  type ConsentActivity,
} from "./security-activity";
import { telegramRoutes } from "./telegram";

type AppEnv = { Bindings: Env };

interface InvitationInput {
  email: string;
  role?: unknown;
}

interface PasskeyMutationInput {
  id: string;
  name?: string;
}

interface PasskeyCountRow {
  count: number;
}

interface AuthorizationRow {
  id: string;
  client_id: string;
  client_name: string | null;
  client_uri: string | null;
  scopes: string;
  created_at: string;
  updated_at: string;
}

interface ConsentClientRow {
  client_id: string;
}

interface ConsentClientInfoRow {
  clientId: string;
  name: string | null;
  disabled: number | null;
  redirectUris: string;
  scopes: string | null;
  tos: string | null;
  policy: string | null;
  metadata: string | null;
}

interface AuthRedirectPayload {
  redirect: true;
  url: string;
}

interface OAuthMetadata {
  token_endpoint_auth_methods_supported?: unknown;
  [key: string]: unknown;
}

// `/update-user` and `/unlink-account` are intentionally absent (and listed in
// `disabledPaths` in auth.ts): profile updates and unlinking go through the
// validated first-party routes in worker/account.ts instead.
const AUTH_EXACT_PATHS = new Set([
  "/change-email",
  "/delete-user",
  "/error",
  "/get-access-token",
  "/get-session",
  "/link-social",
  "/list-accounts",
  "/list-sessions",
  "/ok",
  "/refresh-token",
  "/revoke-other-sessions",
  "/revoke-session",
  "/revoke-sessions",
  "/sign-out",
]);

const AUTH_PATH_PREFIXES = [
  "/.well-known/",
  "/callback/",
  "/oauth2/",
  "/passkey/",
  "/sign-in/",
];

const OAUTH_METADATA_PATHS = new Set([
  "/.well-known/oauth-authorization-server",
  "/.well-known/openid-configuration",
]);

const DEV_CSP_NONCE = "cGc3Mi12aXRlLWRldg==";
const PASSKEY_NAME_MAX_LENGTH = 64;
const FRESH_SESSION_MAX_AGE_MS = 10 * 60 * 1000;

function isAuthPath(pathname: string): boolean {
  return (
    AUTH_EXACT_PATHS.has(pathname) ||
    AUTH_PATH_PREFIXES.some((prefix) => pathname.startsWith(prefix))
  );
}

function isSensitiveAuthPath(pathname: string): boolean {
  return (
    pathname.startsWith("/sign-in/") ||
    pathname.startsWith("/callback/") ||
    pathname.startsWith("/passkey/") ||
    pathname === "/oauth2/authorize" ||
    pathname === "/oauth2/token" ||
    pathname === "/oauth2/introspect" ||
    pathname === "/oauth2/revoke" ||
    pathname === "/oauth2/register"
  );
}

function isAuthNavigationPath(pathname: string): boolean {
  return (
    pathname.startsWith("/callback/") ||
    pathname === "/oauth2/authorize" ||
    pathname === "/oauth2/end-session"
  );
}

async function normalizeOAuthNavigationRedirect(
  request: Request,
  response: Response,
): Promise<Response> {
  if (
    !response.ok ||
    !response.headers.get("content-type")?.toLowerCase().startsWith("application/json")
  ) {
    return response;
  }

  let payload: Partial<AuthRedirectPayload>;
  try {
    payload = (await response.clone().json()) as Partial<AuthRedirectPayload>;
  } catch {
    return response;
  }
  if (payload.redirect !== true || typeof payload.url !== "string") {
    return response;
  }

  let target: URL;
  try {
    target = new URL(payload.url, request.url);
  } catch {
    return response;
  }
  const isLocalHttp =
    target.protocol === "http:" &&
    (target.hostname === "localhost" ||
      target.hostname === "127.0.0.1" ||
      target.hostname === "[::1]");
  if ((target.protocol !== "https:" && !isLocalHttp) || target.username || target.password) {
    return response;
  }

  const headers = new Headers(response.headers);
  headers.delete("Content-Length");
  headers.delete("Content-Type");
  headers.set("Location", target.toString());
  return new Response(null, { status: 302, headers });
}

async function advertiseManagedPublicClients(response: Response): Promise<Response> {
  if (
    !response.ok ||
    !response.headers.get("content-type")?.toLowerCase().startsWith("application/json")
  ) {
    return response;
  }

  let metadata: OAuthMetadata;
  try {
    metadata = (await response.clone().json()) as OAuthMetadata;
  } catch {
    return response;
  }
  const methods = metadata.token_endpoint_auth_methods_supported;
  if (!Array.isArray(methods) || methods.some((method) => typeof method !== "string")) {
    return response;
  }
  if (!methods.includes("none")) methods.unshift("none");

  const headers = new Headers(response.headers);
  headers.delete("Content-Length");
  return new Response(JSON.stringify(metadata), {
    status: response.status,
    headers,
  });
}

async function usesResourceIndicator(request: Request): Promise<boolean> {
  const url = new URL(request.url);
  if (url.searchParams.has("resource")) return true;
  if (url.pathname !== "/oauth2/token" || request.method !== "POST") {
    return false;
  }

  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.startsWith("application/x-www-form-urlencoded")) {
    return false;
  }

  const body = await request.clone().formData();
  return body.has("resource");
}

function validEmail(email: string): boolean {
  return (
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) &&
    !email.includes("..")
  );
}

function validUserId(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  );
}

function parseScopes(value: string): string[] {
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) && parsed.every((scope) => typeof scope === "string")
      ? parsed
      : [];
  } catch {
    return [];
  }
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

export const app = new Hono<AppEnv>();

app.use("*", async (c, next) => {
  const requestId = crypto.randomUUID();
  const startedAt = performance.now();
  c.header("X-Request-Id", requestId);

  await next();

  // The Telegram Login Widget loads a script from telegram.org and renders an
  // iframe from oauth.telegram.org. Allow exactly those two hosts, and only when
  // Telegram is actually configured, so the auth origin's CSP is not widened
  // otherwise. Everything else stays 'self'.
  const telegramEnabled = Boolean(c.env.TELEGRAM_BOT_TOKEN);
  const scriptBase =
    c.env.ENVIRONMENT === "development"
      ? `script-src 'self' 'nonce-${DEV_CSP_NONCE}'`
      : "script-src 'self'";
  const scriptSource = telegramEnabled
    ? `${scriptBase} https://telegram.org`
    : scriptBase;
  const styleSource =
    c.env.ENVIRONMENT === "development"
      ? `style-src 'self' 'nonce-${DEV_CSP_NONCE}'`
      : "style-src 'self'";
  c.header("Content-Security-Policy", [
    "default-src 'self'",
    "base-uri 'self'",
    "connect-src 'self'",
    "font-src 'self'",
    "form-action 'self' https://accounts.google.com",
    "frame-ancestors 'none'",
    telegramEnabled ? "frame-src https://oauth.telegram.org" : "frame-src 'none'",
    "img-src 'self' data: https://lh3.googleusercontent.com",
    "object-src 'none'",
    scriptSource,
    styleSource,
  ].join("; "));
  c.header("Permissions-Policy", "publickey-credentials-create=(self), publickey-credentials-get=(self)");
  c.header("Referrer-Policy", "no-referrer");
  c.header("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");

  const pathname = new URL(c.req.url).pathname;
  if (pathname.startsWith("/.well-known/")) {
    c.header("Cache-Control", "public, max-age=300, stale-while-revalidate=60");
  } else if (pathname.startsWith("/api/avatar/")) {
    // Generated avatars are deterministic public images; the route sets its
    // own long-lived Cache-Control instead of the API no-store default.
  } else if (
    (c.req.method === "GET" || c.req.method === "HEAD") &&
    /^\/api\/account\/avatar\/[^/]+$/.test(pathname)
  ) {
    // Served uploaded avatars are immutable per id; the route sets its own
    // long-lived Cache-Control. `/api/account/avatar` and `.../avatar/mode`
    // stay on the no-store default below (POST, or not matched here).
  } else if (isAuthPath(pathname) || pathname.startsWith("/api/")) {
    c.header("Cache-Control", "no-store");
  }

  console.log(
    JSON.stringify({
      event: "http_request",
      requestId,
      method: c.req.method,
      pathname,
      status: c.res.status,
      durationMs: Math.round(performance.now() - startedAt),
    }),
  );
});

app.use(
  "/api/admin/*",
  bodyLimit({
    maxSize: 4 * 1024,
    onError: (c) => c.json({ error: "request_too_large" }, 413),
  }),
);

app.use("/api/admin/*", async (c, next) => {
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

app.route("/api/admin/clients", adminClientRoutes);
app.route("/api/admin/oauth-reports", adminOauthReportRoutes);
app.route("/api/admin/users", adminUserRoutes);
app.route("/", accountRoutes);
app.route("/", oauthReportRoutes);
app.route("/", telegramRoutes);

app.use(
  "/oauth2/token",
  bodyLimit({
    maxSize: 16 * 1024,
    onError: (c) => c.json({ error: "invalid_request" }, 413),
  }),
);

for (const path of ["/passkey/update-passkey", "/passkey/delete-passkey"]) {
  app.use(
    path,
    bodyLimit({
      maxSize: 4 * 1024,
      onError: (c) => c.json({ error: "request_too_large" }, 413),
    }),
  );
  app.use(path, async (c, next) => {
    const config = readRuntimeConfig(c.env);
    if (c.req.header("origin") !== config.authBaseUrl) {
      return c.json({ error: "invalid_origin" }, 403);
    }
    await next();
  });
}

app.get("/health", (c) =>
  c.json({ status: "ok", service: "pg72-id", version: "0.1.0" }),
);

app.get("/ready", async (c) => {
  await c.env.PG72_ID_DB.prepare("SELECT 1 AS ready").first();
  return c.json({ status: "ready" });
});

// Public: which optional social login providers are configured, so the sign-in
// page only renders buttons that can actually complete. A provider activates
// only when both its id and secret env vars are present (mirrors auth.ts). No
// secret value is exposed. Telegram has its own /api/auth/telegram/config.
app.get("/api/auth/social-config", (c) => {
  const enabled: string[] = [];
  if (c.env.DISCORD_CLIENT_ID && c.env.DISCORD_CLIENT_SECRET) enabled.push("discord");
  if (c.env.GITHUB_CLIENT_ID && c.env.GITHUB_CLIENT_SECRET) enabled.push("github");
  if (c.env.FACEBOOK_CLIENT_ID && c.env.FACEBOOK_CLIENT_SECRET) enabled.push("facebook");
  if (c.env.APPLE_CLIENT_ID && c.env.APPLE_CLIENT_SECRET) enabled.push("apple");
  return c.json({ enabled }, 200, { "Cache-Control": "no-store" });
});

app.post("/passkey/update-passkey", async (c) => {
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

  const input = await readJson<PasskeyMutationInput>(c.req.raw);
  const id = input?.id ?? "";
  const name = input?.name?.trim() ?? "";
  if (!validUserId(id) || !name || name.length > PASSKEY_NAME_MAX_LENGTH) {
    return c.json({ error: "invalid_passkey_update" }, 400);
  }

  const update = await c.env.PG72_ID_DB.prepare(
    "UPDATE passkey SET name = ? WHERE id = ? AND userId = ?",
  )
    .bind(name, id, session.user.id)
    .run();
  if (update.meta.changes !== 1) {
    return c.json({ error: "passkey_not_found" }, 404);
  }

  const passkey = await c.env.PG72_ID_DB.prepare(
    `SELECT id, name, publicKey, userId, credentialID, counter, deviceType,
            backedUp, transports, createdAt, aaguid
       FROM passkey
      WHERE id = ? AND userId = ?`,
  )
    .bind(id, session.user.id)
    .first();

  try {
    await recordAudit(
      c.env,
      {
        eventType: "passkey.renamed",
        outcome: "success",
        subjectId: session.user.id,
        metadata: { passkeyId: id },
      },
      c.executionCtx,
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "passkey_rename_audit_failed",
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
  }

  return c.json({ passkey });
});

app.post("/passkey/delete-passkey", async (c) => {
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

  const input = await readJson<PasskeyMutationInput>(c.req.raw);
  const id = input?.id ?? "";
  if (!validUserId(id)) {
    return c.json({ error: "invalid_passkey_delete" }, 400);
  }

  const ownedPasskey = await c.env.PG72_ID_DB.prepare(
    "SELECT id FROM passkey WHERE id = ? AND userId = ?",
  )
    .bind(id, session.user.id)
    .first();
  if (!ownedPasskey) {
    return c.json({ error: "passkey_not_found" }, 404);
  }

  const passkeyCount = await c.env.PG72_ID_DB.prepare(
    "SELECT COUNT(*) AS count FROM passkey WHERE userId = ?",
  )
    .bind(session.user.id)
    .first<PasskeyCountRow>();
  if ((passkeyCount?.count ?? 0) <= 1) {
    // Deleting the last passkey is forbidden outright when no linked account
    // remains: the user must always keep at least one sign-in method.
    const accountCount = await c.env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM account WHERE userId = ?",
    )
      .bind(session.user.id)
      .first<PasskeyCountRow>();
    if ((accountCount?.count ?? 0) === 0) {
      try {
        await recordAudit(
          c.env,
          {
            eventType: "passkey.delete_blocked",
            outcome: "denied",
            subjectId: session.user.id,
            metadata: { passkeyId: id },
          },
          c.executionCtx,
        );
      } catch (error) {
        console.error(
          JSON.stringify({
            event: "passkey_delete_blocked_audit_failed",
            error: error instanceof Error ? error.name : "UnknownError",
          }),
        );
      }
      return c.json(
        {
          error: "last_login_method",
          message: "The last remaining sign-in method cannot be removed.",
        },
        409,
      );
    }

    const createdAt = new Date(session.session.createdAt).getTime();
    const sessionIsFresh =
      Number.isFinite(createdAt) && Date.now() - createdAt < FRESH_SESSION_MAX_AGE_MS;
    if (!sessionIsFresh) {
      try {
        await recordAudit(
          c.env,
          {
            eventType: "passkey.delete_blocked",
            outcome: "denied",
            subjectId: session.user.id,
            metadata: { passkeyId: id },
          },
          c.executionCtx,
        );
      } catch (error) {
        console.error(
          JSON.stringify({
            event: "passkey_delete_blocked_audit_failed",
            error: error instanceof Error ? error.name : "UnknownError",
          }),
        );
      }
      return c.json(
        {
          code: "SESSION_NOT_FRESH",
          error: "fresh_session_required",
          message: "A fresh session is required to delete the last passkey.",
        },
        403,
      );
    }
  }

  const deletion = await c.env.PG72_ID_DB.prepare(
    "DELETE FROM passkey WHERE id = ? AND userId = ?",
  )
    .bind(id, session.user.id)
    .run();
  if (deletion.meta.changes !== 1) {
    return c.json({ error: "passkey_not_found" }, 404);
  }

  try {
    await recordAudit(
      c.env,
      {
        eventType: "passkey.deleted",
        outcome: "success",
        subjectId: session.user.id,
        metadata: { passkeyId: id },
      },
      c.executionCtx,
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "passkey_delete_audit_failed",
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
  }

  return c.json({ status: true });
});

app.get("/api/account/audit", async (c) => {
  const auth = createAuth(c.env, c.executionCtx);
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session || session.user.status !== "active") {
    return c.json({ error: "unauthorized" }, 401);
  }

  const events = await c.env.PG72_ID_DB.prepare(
    `SELECT id, event_type, outcome, occurred_at
       FROM audit_event
      WHERE subject_id = ?
      ORDER BY occurred_at DESC
      LIMIT 30`,
  )
    .bind(session.user.id)
    .all();

  return c.json({ events: events.results });
});

/**
 * Serves the client identity shown on the consent screen. Every field comes
 * from the D1 client registration written by an administrator; nothing from
 * the authorization request query can influence the response, which is what
 * prevents a client from impersonating another application's name, developer,
 * or destination hosts.
 */
app.get("/api/consent/client", async (c) => {
  const auth = createAuth(c.env, c.executionCtx);
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session || session.user.status !== "active") {
    return c.json({ error: "unauthorized" }, 401);
  }

  const clientId = c.req.query("client_id") ?? "";
  if (!clientId || clientId.length > 256) {
    return c.json({ error: "invalid_client_id" }, 400);
  }

  const row = await c.env.PG72_ID_DB.prepare(
    `SELECT clientId, name, disabled, redirectUris, scopes, tos, policy,
            metadata
       FROM oauthClient
      WHERE clientId = ?
      LIMIT 1`,
  )
    .bind(clientId)
    .first<ConsentClientInfoRow>();
  if (!row || row.disabled === 1) {
    return c.json({ error: "client_not_found" }, 404);
  }

  const metadata = parseClientMetadataRecord(row.metadata);
  return c.json({
    client: {
      clientId: row.clientId,
      name: row.name ?? row.clientId,
      developerName: developerNameFromMetadata(metadata),
      // Trust links are re-validated on read so a row written outside the
      // admin API can never place a non-HTTPS link on the consent screen.
      privacyPolicyUrl: trustUrlOrNull(row.policy),
      termsOfServiceUrl: trustUrlOrNull(row.tos),
      // Derived from the registered redirect URIs only; the redirect_uri
      // query parameter of the live request is validated against the same
      // registration by the OAuth provider before consent is ever shown.
      redirectHosts: redirectHostsFromUris(parseScopes(row.redirectUris)),
      scopes: parseScopes(row.scopes ?? "[]"),
    },
  });
});

app.get("/api/account/authorizations", async (c) => {
  const auth = createAuth(c.env, c.executionCtx);
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session || session.user.status !== "active") {
    return c.json({ error: "unauthorized" }, 401);
  }

  const config = readRuntimeConfig(c.env);
  const result = await c.env.PG72_ID_DB.prepare(
    `SELECT consent.id,
            consent.clientId AS client_id,
            client.name AS client_name,
            client.uri AS client_uri,
            consent.scopes,
            consent.createdAt AS created_at,
            consent.updatedAt AS updated_at
       FROM oauthConsent AS consent
      JOIN oauthClient AS client ON client.clientId = consent.clientId
      WHERE consent.userId = ?
        AND consent.id = (
          SELECT latest.id
            FROM oauthConsent AS latest
           WHERE latest.userId = consent.userId
             AND latest.clientId = consent.clientId
           ORDER BY latest.updatedAt DESC, latest.id DESC
           LIMIT 1
        )
      ORDER BY consent.updatedAt DESC`,
  )
    .bind(session.user.id)
    .all<AuthorizationRow>();

  return c.json({
    authorizations: result.results.map((authorization) => ({
      id: authorization.id,
      clientId: authorization.client_id,
      name: authorization.client_name ?? authorization.client_id,
      uri: authorization.client_uri,
      scopes: parseScopes(authorization.scopes),
      createdAt: authorization.created_at,
      updatedAt: authorization.updated_at,
    })),
    canDeleteAccount:
      normalizeEmail(session.user.email) !== config.bootstrapAdminEmail,
  });
});

app.delete("/api/account/authorizations/:consentId", async (c) => {
  const config = readRuntimeConfig(c.env);
  if (c.req.header("origin") !== config.authBaseUrl) {
    return c.json({ error: "invalid_origin" }, 403);
  }

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

  const consentId = c.req.param("consentId");
  if (!validUserId(consentId)) {
    return c.json({ error: "invalid_consent" }, 400);
  }

  const consent = await c.env.PG72_ID_DB.prepare(
    `SELECT clientId AS client_id
       FROM oauthConsent
      WHERE id = ? AND userId = ?
      LIMIT 1`,
  )
    .bind(consentId, session.user.id)
    .first<ConsentClientRow>();
  if (!consent) {
    return c.json({ error: "authorization_not_found" }, 404);
  }

  const results = await c.env.PG72_ID_DB.batch([
    c.env.PG72_ID_DB.prepare(
      `DELETE FROM verification
        WHERE CASE WHEN json_valid(value) THEN
          json_extract(value, '$.type') = 'authorization_code'
          AND json_extract(value, '$.userId') = ?
          AND json_extract(value, '$.query.client_id') = ?
        ELSE 0 END`,
    ).bind(session.user.id, consent.client_id),
    c.env.PG72_ID_DB.prepare(
      "DELETE FROM oauthAccessToken WHERE userId = ? AND clientId = ?",
    ).bind(session.user.id, consent.client_id),
    c.env.PG72_ID_DB.prepare(
      "DELETE FROM oauthRefreshToken WHERE userId = ? AND clientId = ?",
    ).bind(session.user.id, consent.client_id),
    c.env.PG72_ID_DB.prepare(
      "DELETE FROM oauthConsent WHERE userId = ? AND clientId = ?",
    ).bind(session.user.id, consent.client_id),
  ]);

  if (!results[3]?.meta.changes) {
    return c.json({ error: "authorization_not_found" }, 404);
  }

  try {
    await recordAudit(
      c.env,
      {
        eventType: "oauth.consent_revoked",
        outcome: "success",
        clientId: consent.client_id,
        subjectId: session.user.id,
      },
      c.executionCtx,
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "consent_revoke_audit_failed",
        clientId: consent.client_id,
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
  }

  return c.json({ revoked: true, clientId: consent.client_id });
});

app.post("/api/admin/invitations", async (c) => {
  const gate = await requireAdminPermission(c, "users.invite");
  if (!gate.ok) return gate.response;

  const input = await readJson<InvitationInput>(c.req.raw);
  const email = input?.email ? normalizeEmail(input.email) : "";
  const role = input?.role ?? "user";
  if (!validEmail(email) || !isPlatformRole(role) || role === "bootadmin") {
    return c.json({ error: "invalid_invitation" }, 400);
  }
  // Invitation roles obey the same assignment matrix as direct role
  // changes: only bootadmin can hand out admin.
  if (!ASSIGNABLE_ROLES[gate.actor.role].includes(role)) {
    return c.json({ error: "role_not_assignable" }, 403);
  }

  // Inviting an existing account applies the role immediately as a normal,
  // fully guarded role change. No pending grant is stored: a dormant
  // invitation that silently upgrades an account on a later sign-in would
  // be a privilege escalation ambush.
  const existingUser = await c.env.PG72_ID_DB.prepare(
    "SELECT id, email, role, status FROM user WHERE lower(trim(email)) = ? LIMIT 1",
  )
    .bind(email)
    .first<{ id: string; email: string; role: string | null; status: string }>();
  if (existingUser) {
    const target = await fetchTarget(c, existingUser.id);
    if (!target) {
      return c.json({ error: "user_not_found" }, 404);
    }
    const denial = await deniedRoleChange(
      c,
      gate.actor,
      target,
      role,
      "invitation",
    );
    if (denial === "cannot_modify_self") {
      return c.json({ error: "cannot_modify_self" }, 409);
    }
    if (denial) {
      return c.json({ error: denial }, 403);
    }
    const at = await applyRoleChange(c, gate.actor, target, role, "invitation");
    return c.json({ applied: true, userId: target.row.id, role, at });
  }

  const id = crypto.randomUUID();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

  const result = await c.env.PG72_ID_DB.prepare(
    `INSERT INTO invitation
      (id, email_normalized, role, created_by_user_id, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(email_normalized) DO UPDATE SET
       id = excluded.id,
       role = excluded.role,
       created_by_user_id = excluded.created_by_user_id,
       expires_at = excluded.expires_at,
       revoked_at = NULL,
       created_at = excluded.created_at
     WHERE invitation.consumed_at IS NULL`,
  )
    .bind(
      id,
      email,
      role,
      gate.actor.userId,
      expiresAt.toISOString(),
      now.toISOString(),
    )
    .run();

  if (result.meta.changes !== 1) {
    return c.json({ error: "invitation_already_consumed" }, 409);
  }

  await recordAudit(
    c.env,
    {
      eventType: "invitation.created",
      outcome: "success",
      actorUserId: gate.actor.userId,
      subjectId: id,
      metadata: { role },
    },
    c.executionCtx,
  );

  return c.json(
    { id, email, role, expiresAt: expiresAt.toISOString() },
    201,
  );
});

app.all("*", async (c) => {
  const pathname = new URL(c.req.url).pathname;

  if (isAuthPath(pathname)) {
    if (await usesResourceIndicator(c.req.raw)) {
      return c.json(
        {
          error: "invalid_target",
          error_description:
            "Resource indicators are disabled until the stable provider includes grant binding.",
        },
        400,
      );
    }

    if (isSensitiveAuthPath(pathname)) {
      const ip = c.req.header("cf-connecting-ip") ?? "local";
      const result = await c.env.AUTH_RATE_LIMITER.limit({ key: ip });
      if (!result.success) {
        return c.json({ error: "rate_limited" }, 429);
      }
    }

    const auth = createAuth(c.env, c.executionCtx);

    // For the self security-activity paths (session revocation, passkey
    // registration, consent), capture the actor before the handler runs:
    // revoking sessions can invalidate the current session, so the user id
    // cannot be read afterwards, and the consent body must be cloned before
    // the handler consumes it.
    let activityUserId: string | null = null;
    let consentActivity: ConsentActivity | null = null;
    if (ACTIVITY_AUDIT_PATHS.has(pathname)) {
      const priorSession = await auth.api.getSession({
        headers: c.req.raw.headers,
      });
      activityUserId = priorSession?.user.id ?? null;
      if (activityUserId && pathname === "/oauth2/consent") {
        consentActivity = await parseConsentActivity(c.req.raw);
      }
    }

    const response = await auth.handler(c.req.raw);

    if (activityUserId) {
      // Audit is a source-of-truth write, so it completes before responding.
      await recordAuthPathActivity(
        c.env,
        pathname,
        response,
        activityUserId,
        consentActivity,
        c.executionCtx,
      );
    }

    if (isAuthNavigationPath(pathname)) {
      return normalizeOAuthNavigationRedirect(c.req.raw, response);
    }
    return OAUTH_METADATA_PATHS.has(pathname)
      ? advertiseManagedPublicClients(response)
      : response;
  }

  if (c.req.method !== "GET" && c.req.method !== "HEAD") {
    return c.json({ error: "not_found" }, 404);
  }

  return c.env.ASSETS.fetch(c.req.raw);
});

app.onError((error, c) => {
  console.error(
    JSON.stringify({
      event: "unhandled_error",
      error: error.name,
      pathname: new URL(c.req.url).pathname,
    }),
  );
  return c.json({ error: "internal_server_error" }, 500);
});

export default {
  fetch: app.fetch,
  queue: (batch: MessageBatch<SecurityEvent>, env: Env) =>
    consumeSecurityEvents(batch, env),
} satisfies ExportedHandler<Env, SecurityEvent>;
