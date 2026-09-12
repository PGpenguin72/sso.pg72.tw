import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { constantTimeEqual, makeSignature } from "better-auth/crypto";

import { accountRoutes } from "./account";
import {
  readAccountAccessState,
  recordRestrictedActionDenied,
} from "./account-access";
import {
  ADMIN_ACTOR_COMMIT_PREDICATE,
  adminActorCommitBindings,
} from "./admin-commit";
import { adminClientRoutes } from "./admin-clients";
import { requireAdminPermission } from "./admin-gate";
import { adminLogoutDeliveryRoutes } from "./admin-logout-deliveries";
import {
  adminUserRoutes,
  applyRoleChange,
  deniedRoleChange,
  fetchTarget,
} from "./admin-users";
import {
  auditEventMutationCommitted,
  auditInsertForInvitationMutationStatement,
  consumeSecurityEventMessage,
  createAuditEvent,
  enqueueSecurityEvent,
  isSecurityEvent,
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
import {
  FRESH_SESSION_MAX_AGE_MS,
  MAIL_INTROSPECTION_CLIENT_ID,
  WEBMAIL_CLIENT_ID,
  normalizeEmail,
  readRuntimeConfig,
} from "./config";
import {
  isLogoutDeliveryQueueMessage,
  revokeCentralSessions,
  scheduleLogoutDeliveryDispatch,
  type LogoutDeliveryQueueMessage,
} from "./global-logout";
import { consumeLogoutDeliveryMessage } from "./logout-delivery";
import {
  adminOauthReportRoutes,
  oauthReportRoutes,
} from "./oauth-reports";
import { passkeyStepUpRoutes } from "./passkey-step-up";
import { recoveryCodeManagementRoutes } from "./recovery-codes";
import { requireRecoveryEnabled } from "./recovery-gate";
import { recoveryRoutes } from "./recovery";
import {
  bindPublicRegistrationOAuthState,
  preparePublicRegistrationOAuthStart,
  PUBLIC_REGISTRATION_STATE_KEY,
  publicRegistrationRoutes,
  readStrictJson as readRegistrationJson,
  RegistrationIntentError,
} from "./public-registration";
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

interface AccountChooserSelectInput {
  choiceId?: unknown;
  oauth_query?: unknown;
}

interface AccountChooserUser {
  id: string;
  email: string;
  image?: string | null;
  name: string;
  status?: unknown;
}

interface AccountChooserSession {
  session: {
    token: string;
  };
  user: AccountChooserUser;
}

interface AccountSessionAdoption {
  adopted: boolean;
  cleanupCookieNames?: unknown;
}

interface RegistrationSocialStartInput {
  callbackURL?: unknown;
  intentId?: unknown;
}

interface OAuthMetadata {
  backchannel_logout_session_supported?: unknown;
  backchannel_logout_supported?: unknown;
  token_endpoint_auth_methods_supported?: unknown;
  introspection_endpoint_auth_methods_supported?: unknown;
  revocation_endpoint_auth_methods_supported?: unknown;
  [key: string]: unknown;
}

interface IntrospectionPayload {
  active?: unknown;
  client_id?: unknown;
  email?: unknown;
  email_verified?: unknown;
  error?: unknown;
  exp?: unknown;
  iat?: unknown;
  iss?: unknown;
  scope?: unknown;
}

interface IntrospectionPreflight {
  clientId: string | null;
  response: Response | null;
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
const OAUTH_CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{2,63}$/;
const ACCOUNT_CHOICE_DOMAIN = "pgid-account-choice:v1:";
const ACCOUNT_CHOICE_PATTERN = /^[A-Za-z0-9_-]{32,128}$/;
const OAUTH_QUERY_MAX_LENGTH = 16 * 1024;

async function accountChoiceId(token: string, secret: string): Promise<string> {
  return (await makeSignature(`${ACCOUNT_CHOICE_DOMAIN}${token}`, secret))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function introspectionJson(
  payload: Record<string, unknown>,
  status = 200,
): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json",
      Pragma: "no-cache",
    },
  });
}

export function introspectionRateLimitKeys(
  ip: string,
  clientId: string | null,
): { clientIp: string; ip: string } {
  const clientClass =
    clientId === MAIL_INTROSPECTION_CLIENT_ID ? "mail" : "other";
  return {
    ip: `introspection:ip:${ip}`,
    clientIp: `introspection:${clientClass}:${ip}`,
  };
}

async function introspectionLimitResponse(
  limiter: RateLimit,
  key: string,
): Promise<Response | null> {
  try {
    const result = await limiter.limit({ key });
    return result.success
      ? null
      : introspectionJson({ error: "rate_limited" }, 429);
  } catch {
    return introspectionJson({ error: "temporarily_unavailable" }, 503);
  }
}

async function introspectionPreflight(
  request: Request,
  env: Env,
  ip: string,
): Promise<IntrospectionPreflight> {
  if (request.method !== "POST") {
    return {
      clientId: null,
      response: introspectionJson({ error: "invalid_request" }, 405),
    };
  }

  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  const mediaType = contentType.split(";", 1)[0]?.trim();
  if (mediaType !== "application/x-www-form-urlencoded") {
    return {
      clientId: null,
      response: introspectionJson({ error: "invalid_request" }, 415),
    };
  }
  if (request.headers.has("authorization")) {
    return {
      clientId: null,
      response: introspectionJson({ error: "invalid_request" }, 400),
    };
  }

  let form: FormData;
  try {
    form = await request.clone().formData();
  } catch {
    return {
      clientId: null,
      response: introspectionJson({ error: "invalid_request" }, 400),
    };
  }

  const clientIds = form.getAll("client_id");
  const candidate = clientIds.length === 1 ? clientIds[0] : null;
  const clientId =
    typeof candidate === "string" && OAUTH_CLIENT_ID_PATTERN.test(candidate)
      ? candidate
      : null;
  const duplicateParameter = [
    "client_id",
    "client_secret",
    "token",
    "token_type_hint",
  ].some((name) => form.getAll(name).length > 1);
  const limited = await introspectionLimitResponse(
    env.INTROSPECTION_CLIENT_RATE_LIMITER,
    introspectionRateLimitKeys(ip, clientId).clientIp,
  );
  if (limited) return { clientId, response: limited };
  if (duplicateParameter) {
    return {
      clientId,
      response: introspectionJson({ error: "invalid_request" }, 400),
    };
  }

  return { clientId, response: null };
}

async function normalizeMailIntrospectionResponse(
  clientId: string | null,
  response: Response,
): Promise<Response> {
  let payload: IntrospectionPayload;
  try {
    payload = (await response.clone().json()) as IntrospectionPayload;
  } catch {
    return clientId === MAIL_INTROSPECTION_CLIENT_ID
      ? introspectionJson({ error: "server_error" }, 500)
      : response;
  }

  if (response.status !== 200 && payload.error === "invalid_client") {
    return introspectionJson({ error: "invalid_client" }, 401);
  }
  if (clientId !== MAIL_INTROSPECTION_CLIENT_ID) return response;

  if (response.status !== 200) {
    return introspectionJson(
      {
        error:
          typeof payload.error === "string"
            ? payload.error
            : "invalid_request",
      },
      response.status,
    );
  }

  const scopes =
    typeof payload.scope === "string" ? payload.scope.split(/\s+/) : [];
  if (
    payload.active !== true ||
    payload.client_id !== WEBMAIL_CLIENT_ID ||
    typeof payload.email !== "string" ||
    payload.email.length === 0 ||
    payload.email_verified !== true ||
    !scopes.includes("email")
  ) {
    return introspectionJson({ active: false });
  }

  return introspectionJson({
    active: true,
    client_id: WEBMAIL_CLIENT_ID,
    scope: payload.scope,
    ...(typeof payload.iss === "string" ? { iss: payload.iss } : {}),
    ...(typeof payload.exp === "number" ? { exp: payload.exp } : {}),
    ...(typeof payload.iat === "number" ? { iat: payload.iat } : {}),
    email: payload.email,
    email_verified: true,
  });
}

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
    pathname === "/link-social" ||
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

function appendSetCookieHeaders(target: Headers, source: Headers): void {
  for (const value of source.getSetCookie()) {
    target.append("Set-Cookie", value);
  }
}

function jsonWithSetCookies(
  payload: unknown,
  status: number,
  ...cookieSources: Array<Headers | null>
): Response {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": "application/json",
    Pragma: "no-cache",
  });
  for (const source of cookieSources) {
    if (source) appendSetCookieHeaders(headers, source);
  }
  return new Response(JSON.stringify(payload), { status, headers });
}

function responseWithSetCookies(response: Response, source: Headers | null): Response {
  if (!source) return response;
  const headers = new Headers(response.headers);
  appendSetCookieHeaders(headers, source);
  return new Response(response.body, {
    headers,
    status: response.status,
    statusText: response.statusText,
  });
}

function boundedAccountImage(value: string | null | undefined, baseURL: string): string | null {
  if (!value || value.length > 2_048) return null;
  if (value.startsWith("/") && !value.startsWith("//")) return value;
  try {
    const image = new URL(value);
    const base = new URL(baseURL);
    if (
      image.protocol === "https:" &&
      !image.username &&
      !image.password &&
      (image.origin === base.origin || image.hostname === "lh3.googleusercontent.com")
    ) {
      return image.toString();
    }
  } catch {
    return null;
  }
  return null;
}

function accountChoiceDisplay(
  account: AccountChooserSession,
  activeToken: string | null,
  choiceId: string,
  baseURL: string,
) {
  return {
    active: account.session.token === activeToken,
    choiceId,
    email: account.user.email.trim().slice(0, 254),
    image: boundedAccountImage(account.user.image, baseURL),
    name: account.user.name.trim().slice(0, 120) || "PGID 使用者",
  };
}

function activeAccountSessions(
  sessions: AccountChooserSession[],
): AccountChooserSession[] {
  const seen = new Set<string>();
  return sessions.filter((session) => {
    if (session.user.status !== "active" || seen.has(session.user.id)) return false;
    seen.add(session.user.id);
    return true;
  });
}

function safeOAuthRedirect(value: string, requestURL: string): string | null {
  try {
    const target = new URL(value, requestURL);
    const isLocalHttp =
      target.protocol === "http:" &&
      (target.hostname === "localhost" ||
        target.hostname === "127.0.0.1" ||
        target.hostname === "[::1]");
    return (target.protocol === "https:" || isLocalHttp) &&
      !target.username &&
      !target.password
      ? target.toString()
      : null;
  } catch {
    return null;
  }
}

function canonicalizeOAuthQuery(params: URLSearchParams): string {
  const entries = [...params.entries()].sort(([keyA, valueA], [keyB, valueB]) => {
    if (keyA < keyB) return -1;
    if (keyA > keyB) return 1;
    if (valueA < valueB) return -1;
    if (valueA > valueB) return 1;
    return 0;
  });
  const canonical = new URLSearchParams();
  for (const [key, value] of entries) canonical.append(key, value);
  return canonical.toString();
}

async function isVerifiedProviderOAuthQuery(
  params: URLSearchParams,
  secret: string,
): Promise<boolean> {
  const signatures = params.getAll("sig");
  const expiresAt = Number(params.get("exp"));
  const issuedAt = Number(params.get("ba_iat"));
  if (
    signatures.length !== 1 ||
    !signatures[0] ||
    !Number.isFinite(expiresAt) ||
    expiresAt * 1_000 < Date.now() ||
    !Number.isFinite(issuedAt) ||
    issuedAt <= 0
  ) {
    return false;
  }

  const unsigned = new URLSearchParams(params);
  unsigned.delete("sig");
  const markerNames = params.getAll("ba_param");
  const expectedMarkerNames = [...new Set(unsigned.keys())].sort();
  if (
    markerNames.length !== expectedMarkerNames.length ||
    markerNames.some((name, index) => name !== expectedMarkerNames[index]) ||
    !expectedMarkerNames.includes("ba_iat") ||
    !expectedMarkerNames.includes("ba_param") ||
    !expectedMarkerNames.includes("exp")
  ) {
    return false;
  }

  const expectedSignature = await makeSignature(
    canonicalizeOAuthQuery(unsigned),
    secret,
  );
  return constantTimeEqual(signatures[0], expectedSignature);
}

export async function rewriteDormantAccountSignIn(
  auth: ReturnType<typeof createAuth>,
  request: Request,
  response: Response,
  oauthQuerySecret: string,
): Promise<Response> {
  let target: URL;
  const location = response.headers.get("location");
  const redirectsWithLocation =
    response.status >= 300 && response.status < 400 && location !== null;
  if (redirectsWithLocation) {
    try {
      target = new URL(location, request.url);
    } catch {
      return response;
    }
  } else {
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
    if (payload.redirect !== true || typeof payload.url !== "string") return response;
    try {
      target = new URL(payload.url, request.url);
    } catch {
      return response;
    }
  }
  const requestURL = new URL(request.url);
  const requestPrompt = new Set(
    (requestURL.searchParams.get("prompt") ?? "")
      .split(/\s+/)
      .filter(Boolean),
  );
  const exactAuthorizeRequest =
    request.method === "GET" && requestURL.pathname === "/oauth2/authorize";
  const silentAccountSelection =
    exactAuthorizeRequest &&
    requestPrompt.size === 1 &&
    requestPrompt.has("none") &&
    target.searchParams.get("error") === "login_required";
  const targetPrompt = new Set(
    (target.searchParams.get("prompt") ?? "").split(/\s+/).filter(Boolean),
  );
  const verifiedProviderPrompt =
    exactAuthorizeRequest &&
    target.origin === requestURL.origin &&
    target.pathname === "/sign-in"
      ? await isVerifiedProviderOAuthQuery(
          target.searchParams,
          oauthQuerySecret,
        )
      : false;
  const interactiveAccountSelection =
    verifiedProviderPrompt &&
    !requestPrompt.has("none") &&
    !requestPrompt.has("login") &&
    !requestPrompt.has("create") &&
    !targetPrompt.has("none") &&
    !targetPrompt.has("login") &&
    !targetPrompt.has("create");
  if (!silentAccountSelection && !interactiveAccountSelection) {
    return response;
  }

  if (silentAccountSelection) {
    const current = await auth.api.getSession({ headers: request.headers });
    if (current) return response;
  }
  const remembered = (await auth.api.listDeviceSessions({
    headers: request.headers,
  })) as AccountChooserSession[];
  if (activeAccountSessions(remembered).length === 0) return response;

  if (silentAccountSelection) {
    target.searchParams.set("error", "account_selection_required");
    target.searchParams.set(
      "error_description",
      "End-User account selection is required",
    );
  } else {
    target.pathname = "/select-account";
  }
  const headers = new Headers(response.headers);
  headers.delete("Content-Length");
  if (redirectsWithLocation) {
    headers.set("Location", target.toString());
    return new Response(response.body, {
      headers,
      status: response.status,
      statusText: response.statusText,
    });
  }
  return new Response(
    JSON.stringify({ redirect: true, url: target.toString() } satisfies AuthRedirectPayload),
    { status: response.status, headers },
  );
}

async function advertiseManagedClientAuthMethods(
  response: Response,
  pathname: string,
): Promise<Response> {
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
  // Better Auth 1.6.23 accepts both methods internally, but its Basic parser
  // does not form-url-decode RFC 6749 credentials. Advertise only the PGID
  // contract so discovery-driven clients do not select the broken path.
  metadata.token_endpoint_auth_methods_supported = [
    "none",
    "client_secret_post",
  ];
  metadata.introspection_endpoint_auth_methods_supported = [
    "client_secret_post",
  ];
  metadata.revocation_endpoint_auth_methods_supported = [
    "none",
    "client_secret_post",
  ];
  if (pathname === "/.well-known/openid-configuration") {
    metadata.backchannel_logout_supported = true;
    metadata.backchannel_logout_session_supported = true;
  }

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

async function readJson<T>(
  request: { headers: Headers; json(): Promise<unknown> },
): Promise<T | null> {
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

export const HTML_CACHE_CONTROL =
  "public, no-transform, max-age=0, must-revalidate";

export function isHtmlDocumentResponse(
  method: string,
  status: number,
  contentType: string | null,
): boolean {
  return (
    (method === "GET" || method === "HEAD") &&
    status === 200 &&
    (contentType?.toLowerCase().startsWith("text/html") ?? false)
  );
}

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
  const turnstileEnabled =
    c.env.REGISTRATION_MODE === "public" && Boolean(c.env.TURNSTILE_SITE_KEY);
  const scriptBase =
    c.env.ENVIRONMENT === "development"
      ? `script-src 'self' 'nonce-${DEV_CSP_NONCE}'`
      : "script-src 'self'";
  const scriptSource = telegramEnabled
    ? `${scriptBase} https://telegram.org`
    : scriptBase;
  const registrationScriptSource = turnstileEnabled
    ? `${scriptSource} https://challenges.cloudflare.com`
    : scriptSource;
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
    telegramEnabled || turnstileEnabled
      ? `frame-src${telegramEnabled ? " https://oauth.telegram.org" : ""}${turnstileEnabled ? " https://challenges.cloudflare.com" : ""}`
      : "frame-src 'none'",
    "img-src 'self' data: https://lh3.googleusercontent.com",
    "object-src 'none'",
    registrationScriptSource,
    styleSource,
  ].join("; "));
  c.header("Permissions-Policy", "publickey-credentials-create=(self), publickey-credentials-get=(self)");
  c.header("Referrer-Policy", "no-referrer");
  c.header("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");

  const pathname = new URL(c.req.url).pathname;
  if (isHtmlDocumentResponse(c.req.method, c.res.status, c.res.headers.get("content-type"))) {
    // Cloudflare Web Analytics automatic setup rewrites HTML to inject its
    // beacon. The auth origin intentionally keeps third-party scripts outside
    // its CSP, so prevent that edge rewrite instead of weakening script-src.
    c.header("Cache-Control", HTML_CACHE_CONTROL);
  } else if (pathname.startsWith("/.well-known/")) {
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

app.use(
  "/api/account/passkey-step-up/*",
  bodyLimit({
    maxSize: 16 * 1024,
    onError: (c) => c.json({ error: "request_too_large" }, 413),
  }),
);

app.use("/api/account/passkey-step-up/*", async (c, next) => {
  const config = readRuntimeConfig(c.env);
  if (c.req.header("origin") !== config.authBaseUrl) {
    return c.json({ error: "invalid_origin" }, 403);
  }
  await next();
});

for (const path of [
  "/api/account/recovery-codes",
  "/api/account/recovery-codes/*",
]) {
  // Keep the runtime kill switch ahead of every body reader. Disabled
  // recovery surfaces return the same 404 without touching request bodies or
  // authentication, D1, Queue, and rate-limit bindings.
  app.use(path, requireRecoveryEnabled);
  app.use(
    path,
    bodyLimit({
      maxSize: 1024,
      onError: (c) => c.json({ error: "request_too_large" }, 413),
    }),
  );
  app.use(path, async (c, next) => {
    const config = readRuntimeConfig(c.env);
    if (!config.recoveryEnabled) {
      await next();
      return;
    }
    const origin = c.req.header("origin");
    const readOnly = c.req.method === "GET" || c.req.method === "HEAD";
    if (
      readOnly
        ? origin !== undefined && origin !== config.authBaseUrl
        : origin !== config.authBaseUrl
    ) {
      return c.json({ error: "invalid_origin" }, 403);
    }
    await next();
  });
}

app.use(
  "/api/recovery/start",
  requireRecoveryEnabled,
);
app.use(
  "/api/recovery/start",
  bodyLimit({
    maxSize: 1024,
    onError: (c) => c.json({ error: "request_too_large" }, 413),
  }),
);
app.use(
  "/api/recovery/*",
  requireRecoveryEnabled,
);
app.use(
  "/api/recovery/*",
  bodyLimit({
    maxSize: 64 * 1024,
    onError: (c) => c.json({ error: "request_too_large" }, 413),
  }),
);
app.use("/api/recovery/*", async (c, next) => {
  const config = readRuntimeConfig(c.env);
  if (!config.recoveryEnabled) {
    await next();
    return;
  }
  const origin = c.req.header("origin");
  const readOnly = c.req.method === "GET" || c.req.method === "HEAD";
  if (
    readOnly
      ? origin !== undefined && origin !== config.authBaseUrl
      : origin !== config.authBaseUrl
  ) {
    return c.json({ error: "invalid_origin" }, 403);
  }
  await next();
});

app.route("/api/admin/clients", adminClientRoutes);
app.route("/api/admin/logout-deliveries", adminLogoutDeliveryRoutes);
app.route("/api/admin/oauth-reports", adminOauthReportRoutes);
app.route("/api/admin/users", adminUserRoutes);
app.route("/", passkeyStepUpRoutes);
app.route("/", recoveryCodeManagementRoutes);
app.route("/", recoveryRoutes);
app.route("/", accountRoutes);
app.route("/", oauthReportRoutes);
app.route("/", telegramRoutes);
app.route("/", publicRegistrationRoutes);

app.use(
  "/api/registration/social-start",
  bodyLimit({
    maxSize: 4 * 1024,
    onError: (c) => c.json({ error: "request_too_large" }, 413),
  }),
);

app.post("/api/registration/social-start", async (c) => {
  const config = readRuntimeConfig(c.env);
  if (!config.publicRegistration) {
    return c.json({ error: "registration_not_open" }, 403);
  }
  if (c.req.header("origin") !== config.authBaseUrl) {
    return c.json({ error: "invalid_origin" }, 403);
  }

  const input = await readRegistrationJson<RegistrationSocialStartInput>(
    c.req.raw,
  );
  if (
    typeof input?.callbackURL !== "string" ||
    typeof input.intentId !== "string"
  ) {
    return c.json({ error: "invalid_registration_start" }, 400);
  }

  const clientIp = c.req.header("cf-connecting-ip") ?? "local";
  try {
    const limit = await c.env.AUTH_RATE_LIMITER.limit({
      key: `registration-social-start:${clientIp}`,
    });
    if (!limit.success) {
      return c.json({ error: "registration_rate_limited" }, 429);
    }
  } catch {
    return c.json({ error: "registration_verification_unavailable" }, 503);
  }

  try {
    const prepared = await preparePublicRegistrationOAuthStart(
      c.env,
      config,
      input.intentId,
    );
    const headers = new Headers(c.req.raw.headers);
    headers.delete("content-length");
    headers.set("content-type", "application/json");
    const auth = createAuth(c.env, c.executionCtx);
    const authResponse = await auth.handler(
      new Request(new URL("/sign-in/social", config.authBaseUrl), {
        method: "POST",
        headers,
        body: JSON.stringify({
          additionalData: {
            [PUBLIC_REGISTRATION_STATE_KEY]: prepared.oauthReference,
          },
          callbackURL: input.callbackURL,
          provider: "google",
          requestSignUp: true,
        }),
      }),
    );
    if (!authResponse.ok) return authResponse;

    let redirect: AuthRedirectPayload;
    try {
      redirect = (await authResponse.clone().json()) as AuthRedirectPayload;
    } catch {
      return c.json({ error: "registration_verification_unavailable" }, 503);
    }
    if (redirect.redirect !== true || typeof redirect.url !== "string") {
      return c.json({ error: "registration_verification_unavailable" }, 503);
    }
    let oauthState: string | null;
    try {
      oauthState = new URL(redirect.url).searchParams.get("state");
    } catch {
      return c.json({ error: "registration_verification_unavailable" }, 503);
    }
    if (!oauthState) {
      return c.json({ error: "registration_verification_unavailable" }, 503);
    }

    await bindPublicRegistrationOAuthState(
      c.env,
      config,
      prepared,
      oauthState,
    );
    return authResponse;
  } catch (error) {
    if (error instanceof RegistrationIntentError) {
      return c.json({ error: error.code }, error.status);
    }
    throw error;
  }
});

app.use("/oauth2/introspect", async (c, next) => {
  const ip = c.req.header("cf-connecting-ip") ?? "local";
  const limited = await introspectionLimitResponse(
    c.env.INTROSPECTION_IP_RATE_LIMITER,
    introspectionRateLimitKeys(ip, null).ip,
  );
  if (limited) return limited;
  await next();
});

app.use(
  "/oauth2/introspect",
  bodyLimit({
    maxSize: 4 * 1024,
    onError: () => introspectionJson({ error: "invalid_request" }, 413),
  }),
);

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

for (const path of [
  "/revoke-session",
  "/revoke-sessions",
  "/revoke-other-sessions",
  "/sign-out",
]) {
  app.use(
    path,
    bodyLimit({
      maxSize: 4 * 1024,
      onError: (c) => c.json({ error: "request_too_large" }, 413),
    }),
  );
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

app.use(
  "/api/account-chooser/select",
  bodyLimit({
    maxSize: OAUTH_QUERY_MAX_LENGTH + 1_024,
    onError: (c) => c.json({ error: "request_too_large" }, 413),
  }),
);

app.get("/api/account-chooser", async (c) => {
  const config = readRuntimeConfig(c.env);
  const origin = c.req.header("origin");
  if (origin !== undefined && origin !== config.authBaseUrl) {
    return c.json({ error: "invalid_origin" }, 403);
  }

  const auth = createAuth(c.env, c.executionCtx);
  const current = await auth.api.getSession({ headers: c.req.raw.headers });
  let adoptionHeaders: Headers | null = null;
  let cleanupHeaders: Headers | null = null;
  if (current?.user.status === "active") {
    const adopted = await auth.api.adoptActiveAccountSession({
      headers: c.req.raw.headers,
      method: "POST",
      returnHeaders: true,
    });
    adoptionHeaders = adopted.headers;
    const adoption = adopted.response as AccountSessionAdoption;
    const cookieNames = Array.isArray(adoption.cleanupCookieNames)
      ? adoption.cleanupCookieNames.filter(
          (name): name is string => typeof name === "string",
        )
      : [];
    if (cookieNames.length > 0) {
      const cleanup = await auth.api.expireRememberedAccountCookies({
        body: { cookieNames },
        headers: c.req.raw.headers,
        method: "POST",
        returnHeaders: true,
      });
      cleanupHeaders = cleanup.headers;
    }
  }

  const remembered = (await auth.api.listDeviceSessions({
    headers: c.req.raw.headers,
  })) as AccountChooserSession[];
  const candidates = activeAccountSessions([
    ...(current?.user.status === "active"
      ? [current as AccountChooserSession]
      : []),
    ...remembered,
  ]);
  const choices = await Promise.all(
    candidates.map(async (account) =>
      accountChoiceDisplay(
        account,
        current?.session.token ?? null,
        await accountChoiceId(account.session.token, c.env.BETTER_AUTH_SECRET),
        config.authBaseUrl,
      ),
    ),
  );

  return jsonWithSetCookies(
    { accounts: choices },
    200,
    adoptionHeaders,
    cleanupHeaders,
  );
});

app.post("/api/account-chooser/select", async (c) => {
  const config = readRuntimeConfig(c.env);
  if (c.req.header("origin") !== config.authBaseUrl) {
    return c.json({ error: "invalid_origin" }, 403);
  }
  const input = await readJson<AccountChooserSelectInput>(c.req.raw);
  if (
    typeof input?.choiceId !== "string" ||
    !ACCOUNT_CHOICE_PATTERN.test(input.choiceId) ||
    typeof input.oauth_query !== "string" ||
    input.oauth_query.length === 0 ||
    input.oauth_query.length > OAUTH_QUERY_MAX_LENGTH
  ) {
    return c.json({ error: "invalid_account_choice" }, 400);
  }

  const auth = createAuth(c.env, c.executionCtx);
  const remembered = (await auth.api.listDeviceSessions({
    headers: c.req.raw.headers,
  })) as AccountChooserSession[];
  const candidates = activeAccountSessions(remembered);
  let selected: AccountChooserSession | null = null;
  for (const candidate of candidates) {
    const candidateId = await accountChoiceId(
      candidate.session.token,
      c.env.BETTER_AUTH_SECRET,
    );
    if (candidateId === input.choiceId) {
      selected = candidate;
      break;
    }
  }
  if (!selected) {
    return c.json({ error: "account_choice_expired" }, 409);
  }

  const setActiveBody = {
    sessionToken: selected.session.token,
    oauth_query: input.oauth_query,
  };
  const selectionHeaders = new Headers(c.req.raw.headers);
  selectionHeaders.set("Accept", "application/json");
  selectionHeaders.set("Content-Type", "application/json");
  selectionHeaders.set("Sec-Fetch-Mode", "cors");
  const continuation = await auth.handler(
    new Request(`${config.authBaseUrl}/multi-session/set-active`, {
      method: "POST",
      headers: selectionHeaders,
      body: JSON.stringify(setActiveBody),
    }),
  );
  if (continuation.status === 400) {
    return c.json({ error: "invalid_authorization_request" }, 400);
  }
  if (continuation.status === 401 || continuation.status === 403) {
    return c.json({ error: "account_choice_expired" }, 409);
  }

  let redirectValue: string | null = null;
  const location = continuation.headers.get("location");
  if (
    continuation.status >= 300 &&
    continuation.status < 400 &&
    location !== null
  ) {
    redirectValue = location;
  } else if (continuation.ok) {
    try {
      const payload = (await continuation.clone().json()) as Partial<AuthRedirectPayload>;
      if (payload.redirect === true && typeof payload.url === "string") {
        redirectValue = payload.url;
      }
    } catch {
      redirectValue = null;
    }
  }
  const url = redirectValue
    ? safeOAuthRedirect(redirectValue, c.req.url)
    : null;
  if (!url) {
    return c.json({ error: "account_continuation_unavailable" }, 503);
  }

  return jsonWithSetCookies(
    { redirect: true, url } satisfies AuthRedirectPayload,
    200,
    continuation.headers,
  );
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
    if (target.effectiveRole === role) {
      const unchanged = await c.env.PG72_ID_DB.prepare(
        "SELECT updatedAt FROM user WHERE id = ? LIMIT 1",
      )
        .bind(target.row.id)
        .first<{ updatedAt: string }>();
      return c.json({
        applied: true,
        userId: target.row.id,
        role,
        at: unchanged?.updatedAt ?? null,
      });
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
    if (!at) return c.json({ error: "user_state_changed" }, 409);
    return c.json({ applied: true, userId: target.row.id, role, at });
  }

  const id = crypto.randomUUID();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

  const event = createAuditEvent({
    eventType: "invitation.created",
    outcome: "success",
    actorUserId: gate.actor.userId,
    subjectId: id,
    metadata: { role },
  });

  // D1 executes this batch as one transaction. The invitation statement is
  // the single commit-time eligibility decision: both the actor/session
  // snapshot and the normalized target's continued absence must hold. The
  // audit statement then depends on the exact new invitation row, so a
  // successful mutation cannot commit without its success audit. Result
  // counts below only distinguish the paired no-op from the paired write.
  const results = await c.env.PG72_ID_DB.batch([
    c.env.PG72_ID_DB.prepare(
      `INSERT INTO invitation
        (id, email_normalized, role, created_by_user_id, expires_at, created_at)
       SELECT ?, ?, ?, ?, ?, ?
        WHERE ${ADMIN_ACTOR_COMMIT_PREDICATE}
          AND NOT EXISTS (
            SELECT 1
              FROM user AS invitation_target
             WHERE lower(trim(invitation_target.email)) = ?
          )
       ON CONFLICT(email_normalized) DO UPDATE SET
         id = excluded.id,
         role = excluded.role,
         created_by_user_id = excluded.created_by_user_id,
         expires_at = excluded.expires_at,
         revoked_at = NULL,
         created_at = excluded.created_at
       WHERE invitation.consumed_at IS NULL`,
    ).bind(
      id,
      email,
      role,
      gate.actor.userId,
      expiresAt.toISOString(),
      now.toISOString(),
      ...adminActorCommitBindings(gate.actor.commitGuard),
      email,
    ),
    auditInsertForInvitationMutationStatement(c.env, event, {
      actorUserId: gate.actor.userId,
      email,
      invitationId: id,
      role,
    }),
  ]);

  if (
    results[0]?.meta.changes !== 1 ||
    !auditEventMutationCommitted(results[1])
  ) {
    return c.json({ error: "management_state_changed" }, 409);
  }
  await enqueueSecurityEvent(c.env, event, c.executionCtx);

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

    const ip = c.req.header("cf-connecting-ip") ?? "local";
    let introspectionClientId: string | null = null;
    if (pathname === "/oauth2/introspect") {
      const preflight = await introspectionPreflight(c.req.raw, c.env, ip);
      introspectionClientId = preflight.clientId;
      if (preflight.response) return preflight.response;
    } else if (isSensitiveAuthPath(pathname)) {
      const result = await c.env.AUTH_RATE_LIMITER.limit({ key: ip });
      if (!result.success) {
        return c.json({ error: "rate_limited" }, 429);
      }
    }

    const auth = createAuth(c.env, c.executionCtx);

    if (
      c.req.method === "POST" &&
      [
        "/revoke-session",
        "/revoke-sessions",
        "/revoke-other-sessions",
        "/sign-out",
      ].includes(pathname)
    ) {
      const config = readRuntimeConfig(c.env);
      if (c.req.header("origin") !== config.authBaseUrl) {
        return c.json({ error: "invalid_origin" }, 403);
      }
      const current = await auth.api.getSession({
        headers: c.req.raw.headers,
      });

      const isSignOut = pathname === "/sign-out";
      const currentOnlyAuth = isSignOut
        ? createAuth(c.env, c.executionCtx, c.env.PG72_ID_DB, {
            multiSession: false,
          })
        : auth;
      if (!current) return currentOnlyAuth.handler(c.req.raw);

      const forgotten = isSignOut
        ? await auth.api.forgetCurrentAccountSession({
            headers: c.req.raw.headers,
            method: "POST",
            returnHeaders: true,
          })
        : null;
      const freshAfter = new Date(
        Date.now() - FRESH_SESSION_MAX_AGE_MS,
      ).toISOString();
      const currentCreatedAt = new Date(current.session.createdAt).getTime();
      if (
        !isSignOut &&
        (!Number.isFinite(currentCreatedAt) ||
          currentCreatedAt <= new Date(freshAfter).getTime())
      ) {
        return auth.handler(c.req.raw);
      }

      let selector:
        | {
            kind: "session";
            sessionId: string;
            token?: string;
            userId: string;
          }
        | { kind: "user_all"; userId: string }
        | {
            kind: "user_others";
            exceptSessionId: string;
            userId: string;
          };
      let eventType: string;
      if (pathname === "/revoke-session") {
        const input = await readJson<{ token?: unknown }>(c.req.raw.clone());
        if (typeof input?.token !== "string" || input.token.length === 0) {
          return auth.handler(c.req.raw);
        }
        const target = await c.env.PG72_ID_DB.prepare(
          "SELECT id FROM session WHERE token = ? AND userId = ? LIMIT 1",
        )
          .bind(input.token, current.user.id)
          .first<{ id: string }>();
        selector = {
          kind: "session",
          sessionId: target?.id ?? crypto.randomUUID(),
          token: input.token,
          userId: current.user.id,
        };
        eventType = "session.revoked";
      } else if (pathname === "/revoke-other-sessions") {
        selector = {
          kind: "user_others",
          exceptSessionId: current.session.id,
          userId: current.user.id,
        };
        eventType = "session.revoked_others";
      } else if (pathname === "/revoke-sessions") {
        selector = { kind: "user_all", userId: current.user.id };
        eventType = "session.revoked_all";
      } else {
        selector = {
          kind: "session",
          sessionId: current.session.id,
          token: current.session.token,
          userId: current.user.id,
        };
        eventType = "session.revoked";
      }

      const revoked = await revokeCentralSessions(
        c.env,
        {
          actorSessionId: current.session.id,
          actorUserId: current.user.id,
          eventType,
          ...(!isSignOut ? { freshAfter } : {}),
          reason: isSignOut ? "sign_out" : "self_revoke",
          selector,
          subjectUserId: current.user.id,
        },
        c.executionCtx,
      );
      if (!revoked.committed) {
        return responseWithSetCookies(
          await currentOnlyAuth.handler(c.req.raw),
          forgotten?.headers ?? null,
        );
      }
      if (isSignOut) {
        return responseWithSetCookies(
          await currentOnlyAuth.handler(c.req.raw),
          forgotten?.headers ?? null,
        );
      }
      return c.json({ status: true });
    }

    if (pathname === "/link-social") {
      const session = await auth.api.getSession({ headers: c.req.raw.headers });
      if (session) {
        const access = await readAccountAccessState(c.env, session.user.id);
        if (!access || access.status !== "active") {
          return c.json({ error: "forbidden" }, 403);
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
      }
    }

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

    let response = await auth.handler(c.req.raw);

    if (pathname === "/oauth2/authorize") {
      response = await rewriteDormantAccountSignIn(
        auth,
        c.req.raw,
        response,
        c.env.BETTER_AUTH_SECRET,
      );
    }

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
    if (pathname === "/oauth2/introspect") {
      return normalizeMailIntrospectionResponse(
        introspectionClientId,
        response,
      );
    }
    return OAUTH_METADATA_PATHS.has(pathname)
      ? advertiseManagedClientAuthMethods(response, pathname)
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

type WorkerQueueMessage = SecurityEvent | LogoutDeliveryQueueMessage;

export default {
  fetch: app.fetch,
  queue: async (batch: MessageBatch<WorkerQueueMessage>, env: Env) => {
    for (const message of batch.messages) {
      if (isLogoutDeliveryQueueMessage(message.body)) {
        await consumeLogoutDeliveryMessage(
          message as Message<LogoutDeliveryQueueMessage>,
          env,
        );
      } else if (isSecurityEvent(message.body)) {
        await consumeSecurityEventMessage(
          message as Message<SecurityEvent>,
          env,
        );
      } else {
        console.error(
          JSON.stringify({ event: "queue_message_rejected", queue: batch.queue }),
        );
        message.ack();
      }
    }
  },
  scheduled: (_controller: ScheduledController, env: Env, ctx: ExecutionContext) => {
    ctx.waitUntil(scheduleLogoutDeliveryDispatch(env));
  },
} satisfies ExportedHandler<Env, WorkerQueueMessage>;
