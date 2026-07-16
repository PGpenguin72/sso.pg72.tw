import { Hono, type Context } from "hono";

import { requireAdminPermission, type AdminActor } from "./admin-gate";
import { recordAudit } from "./audit";
import {
  DEVELOPER_NAME_METADATA_KEY,
  developerNameFromMetadata,
  parseClientMetadataRecord,
  trustUrlOrNull,
  validDeveloperName,
} from "./client-metadata";
import {
  CLIENT_SECRET_PREFIX,
  TRUSTED_CLIENT_IDS,
  readRuntimeConfig,
  type RuntimeConfig,
} from "./config";
import { hasPermission } from "./roles";

type AppEnv = { Bindings: Env };

const ALLOWED_SCOPES = new Set(["openid", "profile", "email", "offline_access"]);
const ALLOWED_GRANT_TYPES = new Set(["authorization_code", "refresh_token"]);
const CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{2,63}$/;
const CLIENT_NAME_MAX_LENGTH = 64;
const CLIENT_URI_MAX_LENGTH = 256;
const REDIRECT_URI_MAX_LENGTH = 512;
const REDIRECT_URI_MAX_COUNT = 8;
const CLIENT_SECRET_BYTES = 32;

interface CreateClientInput {
  clientId?: unknown;
  name?: unknown;
  developerName?: unknown;
  privacyPolicyUrl?: unknown;
  termsOfServiceUrl?: unknown;
  uri?: unknown;
  redirectUris?: unknown;
  postLogoutRedirectUris?: unknown;
  scopes?: unknown;
  grantTypes?: unknown;
  public?: unknown;
  enableEndSession?: unknown;
  tokenEndpointAuthMethod?: unknown;
  skipConsent?: unknown;
}

interface ClientStatusInput {
  disabled?: unknown;
}

interface ClientTrustInput {
  developerName?: unknown;
  privacyPolicyUrl?: unknown;
  termsOfServiceUrl?: unknown;
}

interface AdminClientRow {
  clientId: string;
  name: string | null;
  uri: string | null;
  disabled: number | null;
  public: number | null;
  scopes: string | null;
  redirectUris: string;
  postLogoutRedirectUris: string | null;
  grantTypes: string | null;
  tokenEndpointAuthMethod: string | null;
  tos: string | null;
  policy: string | null;
  metadata: string | null;
  hasSecret?: number;
  clientSecret?: string | null;
  ownerUserId: string | null;
  createdAt: string | null;
  updatedAt: string | null;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

/**
 * Generates the random part of a client secret with Web Crypto. The plaintext
 * secret handed to the operator is `pg72_cs_<suffix>`.
 */
function generateClientSecretSuffix(): string {
  const bytes = new Uint8Array(CLIENT_SECRET_BYTES);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

/**
 * Stored format used by @better-auth/oauth-provider with the default
 * `storeClientSecret: "hashed"` strategy: SHA-256 of the secret without the
 * configured prefix, base64url-encoded without padding.
 */
export async function hashClientSecretSuffix(suffix: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(suffix),
  );
  return toBase64Url(new Uint8Array(digest));
}

/**
 * Exact-match redirect URI validation. Production only accepts canonical
 * HTTPS URIs; development and preview additionally accept loopback HTTP.
 * Wildcards, fragments, and embedded credentials are always rejected.
 */
export function validRedirectUri(
  value: unknown,
  environment: RuntimeConfig["environment"],
): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > REDIRECT_URI_MAX_LENGTH ||
    value.includes("*")
  ) {
    return false;
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.href !== value || url.username || url.password || url.hash !== "") {
    return false;
  }

  if (url.protocol === "https:") return true;
  if (environment === "production") return false;
  return (
    url.protocol === "http:" &&
    (url.hostname === "localhost" ||
      url.hostname === "127.0.0.1" ||
      url.hostname === "[::1]")
  );
}

function validStringArray(
  value: unknown,
  maxCount: number,
): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= maxCount &&
    value.every((entry) => typeof entry === "string")
  );
}

function parseJsonStringArray(value: string | null): string[] {
  if (!value) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) &&
      parsed.every((entry) => typeof entry === "string")
      ? parsed
      : [];
  } catch {
    return [];
  }
}

/**
 * Optional trust URL from the request body. `undefined`, `null`, and the
 * empty string all mean "not provided"; anything else must pass the strict
 * HTTPS validation in trustUrlOrNull.
 */
function optionalTrustUrl(
  value: unknown,
): { ok: true; url: string | null } | { ok: false } {
  if (value === undefined || value === null || value === "") {
    return { ok: true, url: null };
  }
  const url = trustUrlOrNull(value);
  return url ? { ok: true, url } : { ok: false };
}

function clientView(row: AdminClientRow) {
  return {
    clientId: row.clientId,
    name: row.name ?? row.clientId,
    developerName: developerNameFromMetadata(
      parseClientMetadataRecord(row.metadata),
    ),
    privacyPolicyUrl: row.policy,
    termsOfServiceUrl: row.tos,
    uri: row.uri,
    disabled: row.disabled === 1,
    public: row.public === 1,
    scopes: parseJsonStringArray(row.scopes),
    redirectUris: parseJsonStringArray(row.redirectUris),
    postLogoutRedirectUris: parseJsonStringArray(row.postLogoutRedirectUris),
    grantTypes: parseJsonStringArray(row.grantTypes),
    tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
    hasSecret: row.hasSecret === 1,
    trusted: TRUSTED_CLIENT_IDS.has(row.clientId),
    ownerUserId: row.ownerUserId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
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

/**
 * Deletes pending authorization codes issued to a client. Mirrors the
 * verification-table cleanup used by consent revocation in worker/index.ts.
 */
function pendingAuthorizationCodeCleanup(env: Env, clientId: string) {
  return env.PG72_ID_DB.prepare(
    `DELETE FROM verification
      WHERE CASE WHEN json_valid(value) THEN
        json_extract(value, '$.type') = 'authorization_code'
        AND json_extract(value, '$.query.client_id') = ?
      ELSE 0 END`,
  ).bind(clientId);
}

/**
 * Whether the actor may manage every client (admin/bootadmin) or only the
 * clients they own (developer).
 */
function managesAllClients(actor: AdminActor): boolean {
  return hasPermission(actor.role, "clients.manage_all");
}

/**
 * Ownership gate for mutations on an existing client. Developers get a 404
 * for clients they do not own so the endpoint does not leak which client
 * IDs exist.
 */
async function loadManagedClient(
  c: Context<AppEnv>,
  actor: AdminActor,
  clientId: string,
): Promise<{ ownerUserId: string | null } | null> {
  const row = await c.env.PG72_ID_DB.prepare(
    "SELECT ownerUserId FROM oauthClient WHERE clientId = ? LIMIT 1",
  )
    .bind(clientId)
    .first<{ ownerUserId: string | null }>();
  if (!row) return null;
  if (!managesAllClients(actor) && row.ownerUserId !== actor.userId) {
    return null;
  }
  return row;
}

async function auditClientChange(
  c: Context<AppEnv>,
  eventType: string,
  clientId: string,
  adminUserId: string,
): Promise<void> {
  try {
    await recordAudit(
      c.env,
      {
        eventType,
        outcome: "success",
        clientId,
        subjectId: adminUserId,
        actorUserId: adminUserId,
      },
      c.executionCtx,
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "oauth_client_audit_failed",
        eventType,
        clientId,
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
  }
}

export const adminClientRoutes = new Hono<AppEnv>();

adminClientRoutes.get("/", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage");
  if (!gate.ok) return gate.response;

  // Developers only see clients they own; admin/bootadmin see everything,
  // including unowned (NULL owner) clients such as the seeded first-party
  // relying parties.
  const result = await c.env.PG72_ID_DB.prepare(
    `SELECT clientId, name, uri, disabled, public, scopes, redirectUris,
            postLogoutRedirectUris, grantTypes, tokenEndpointAuthMethod,
            tos, policy, metadata,
            CASE WHEN clientSecret IS NOT NULL
                  AND length(trim(clientSecret)) > 0
                 THEN 1 ELSE 0 END AS hasSecret,
            ownerUserId, createdAt, updatedAt
       FROM oauthClient
      WHERE ?1 = 1 OR ownerUserId = ?2
      ORDER BY createdAt DESC, clientId ASC`,
  )
    .bind(managesAllClients(gate.actor) ? 1 : 0, gate.actor.userId)
    .all<AdminClientRow>();

  return c.json({ clients: result.results.map(clientView) });
});

adminClientRoutes.post("/", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage");
  if (!gate.ok) return gate.response;

  const config = readRuntimeConfig(c.env);
  const input = await readJson<CreateClientInput>(c.req.raw);
  if (!input) {
    return c.json({ error: "invalid_request" }, 400);
  }

  // The D1 trigger enforces this too; reject early with a clear error.
  if (input.skipConsent !== undefined && input.skipConsent !== false && input.skipConsent !== 0) {
    return c.json({ error: "skip_consent_not_allowed" }, 400);
  }

  const name = typeof input.name === "string" ? input.name.trim() : "";
  if (!name || name.length > CLIENT_NAME_MAX_LENGTH) {
    return c.json({ error: "invalid_client_name" }, 400);
  }

  // The consent screen must always show who operates the client, so the
  // developer identity is mandatory at creation time and can only be edited
  // by an administrator; it is never read from authorization request input.
  if (!validDeveloperName(input.developerName)) {
    return c.json({ error: "invalid_developer_name" }, 400);
  }
  const developerName = input.developerName.trim();

  const privacyPolicy = optionalTrustUrl(input.privacyPolicyUrl);
  if (!privacyPolicy.ok) {
    return c.json({ error: "invalid_privacy_policy_url" }, 400);
  }
  const termsOfService = optionalTrustUrl(input.termsOfServiceUrl);
  if (!termsOfService.ok) {
    return c.json({ error: "invalid_terms_of_service_url" }, 400);
  }

  let clientId: string;
  if (input.clientId === undefined) {
    clientId = crypto.randomUUID();
  } else if (
    typeof input.clientId === "string" &&
    CLIENT_ID_PATTERN.test(input.clientId)
  ) {
    clientId = input.clientId;
  } else {
    return c.json({ error: "invalid_client_id" }, 400);
  }
  if (TRUSTED_CLIENT_IDS.has(clientId)) {
    return c.json({ error: "trusted_client_locked" }, 409);
  }

  if (
    !validStringArray(input.redirectUris, REDIRECT_URI_MAX_COUNT) ||
    input.redirectUris.length === 0 ||
    !input.redirectUris.every((uri) => validRedirectUri(uri, config.environment)) ||
    new Set(input.redirectUris).size !== input.redirectUris.length
  ) {
    return c.json({ error: "invalid_redirect_uri" }, 400);
  }
  const redirectUris = input.redirectUris;

  let postLogoutRedirectUris: string[] = [];
  if (input.postLogoutRedirectUris !== undefined) {
    if (
      !validStringArray(input.postLogoutRedirectUris, REDIRECT_URI_MAX_COUNT) ||
      !input.postLogoutRedirectUris.every((uri) =>
        validRedirectUri(uri, config.environment),
      )
    ) {
      return c.json({ error: "invalid_post_logout_redirect_uri" }, 400);
    }
    postLogoutRedirectUris = input.postLogoutRedirectUris;
  }

  let scopes = ["openid", "profile", "email"];
  if (input.scopes !== undefined) {
    if (
      !validStringArray(input.scopes, ALLOWED_SCOPES.size) ||
      input.scopes.length === 0 ||
      !input.scopes.every((scope) => ALLOWED_SCOPES.has(scope)) ||
      new Set(input.scopes).size !== input.scopes.length ||
      !input.scopes.includes("openid")
    ) {
      return c.json({ error: "invalid_scopes" }, 400);
    }
    scopes = input.scopes;
  }

  let grantTypes = ["authorization_code"];
  if (input.grantTypes !== undefined) {
    if (
      !validStringArray(input.grantTypes, ALLOWED_GRANT_TYPES.size) ||
      !input.grantTypes.every((grant) => ALLOWED_GRANT_TYPES.has(grant)) ||
      new Set(input.grantTypes).size !== input.grantTypes.length ||
      !input.grantTypes.includes("authorization_code")
    ) {
      return c.json({ error: "invalid_grant_types" }, 400);
    }
    grantTypes = input.grantTypes;
  }
  if (grantTypes.includes("refresh_token") && !scopes.includes("offline_access")) {
    return c.json({ error: "refresh_token_requires_offline_access" }, 400);
  }

  const isPublic = input.public === true;
  if (input.public !== undefined && typeof input.public !== "boolean") {
    return c.json({ error: "invalid_request" }, 400);
  }
  const tokenEndpointAuthMethod = isPublic ? "none" : "client_secret_post";
  if (
    input.tokenEndpointAuthMethod !== undefined &&
    input.tokenEndpointAuthMethod !== tokenEndpointAuthMethod
  ) {
    return c.json({ error: "invalid_token_endpoint_auth_method" }, 400);
  }

  let uri: string | null = null;
  if (input.uri !== undefined) {
    if (
      typeof input.uri !== "string" ||
      input.uri.length > CLIENT_URI_MAX_LENGTH ||
      !validRedirectUri(input.uri, config.environment)
    ) {
      return c.json({ error: "invalid_client_uri" }, 400);
    }
    uri = input.uri;
  }

  const enableEndSession = input.enableEndSession === true;
  if (
    input.enableEndSession !== undefined &&
    typeof input.enableEndSession !== "boolean"
  ) {
    return c.json({ error: "invalid_request" }, 400);
  }

  const existing = await c.env.PG72_ID_DB.prepare(
    "SELECT clientId FROM oauthClient WHERE clientId = ? LIMIT 1",
  )
    .bind(clientId)
    .first();
  if (existing) {
    return c.json({ error: "client_exists" }, 409);
  }

  const clientSecretSuffix = isPublic ? null : generateClientSecretSuffix();
  const storedClientSecret = clientSecretSuffix
    ? await hashClientSecretSuffix(clientSecretSuffix)
    : null;
  const now = new Date().toISOString();

  try {
    await c.env.PG72_ID_DB.prepare(
      `INSERT INTO oauthClient (
        id, clientId, clientSecret, disabled, skipConsent, enableEndSession,
        subjectType, scopes, createdAt, updatedAt, name, uri, redirectUris,
        postLogoutRedirectUris, tokenEndpointAuthMethod, grantTypes,
        responseTypes, public, type, requirePKCE, ownerUserId, tos, policy,
        metadata
      ) VALUES (?, ?, ?, 0, 0, ?, 'public', ?, ?, ?, ?, ?, ?, ?, ?, ?, '["code"]', ?, ?, 1, ?, ?, ?, ?)`,
    )
      .bind(
        crypto.randomUUID(),
        clientId,
        storedClientSecret,
        enableEndSession ? 1 : 0,
        JSON.stringify(scopes),
        now,
        now,
        name,
        uri,
        JSON.stringify(redirectUris),
        postLogoutRedirectUris.length > 0
          ? JSON.stringify(postLogoutRedirectUris)
          : null,
        tokenEndpointAuthMethod,
        JSON.stringify(grantTypes),
        isPublic ? 1 : 0,
        isPublic ? null : "web",
        gate.actor.userId,
        termsOfService.url,
        privacyPolicy.url,
        JSON.stringify({ [DEVELOPER_NAME_METADATA_KEY]: developerName }),
      )
      .run();
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.includes("UNIQUE constraint failed")
    ) {
      return c.json({ error: "client_exists" }, 409);
    }
    throw error;
  }

  await auditClientChange(
    c,
    "oauth_client.created",
    clientId,
    gate.actor.userId,
  );

  return c.json(
    {
      client: {
        clientId,
        name,
        developerName,
        privacyPolicyUrl: privacyPolicy.url,
        termsOfServiceUrl: termsOfService.url,
        uri,
        disabled: false,
        public: isPublic,
        scopes,
        redirectUris,
        postLogoutRedirectUris,
        grantTypes,
        tokenEndpointAuthMethod,
        hasSecret: !isPublic,
        trusted: false,
        ownerUserId: gate.actor.userId,
        createdAt: now,
        updatedAt: now,
      },
      // The plaintext secret is returned exactly once and never stored.
      ...(clientSecretSuffix
        ? { clientSecret: `${CLIENT_SECRET_PREFIX}${clientSecretSuffix}` }
        : {}),
    },
    201,
  );
});

adminClientRoutes.patch("/:clientId", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage");
  if (!gate.ok) return gate.response;

  const clientId = c.req.param("clientId");
  if (!CLIENT_ID_PATTERN.test(clientId)) {
    return c.json({ error: "invalid_client_id" }, 400);
  }
  if (TRUSTED_CLIENT_IDS.has(clientId)) {
    return c.json({ error: "trusted_client_locked" }, 409);
  }
  // Same ownership rule as every other mutation: developers may only edit
  // the trust metadata of clients they own (404 keeps client IDs private).
  if (!(await loadManagedClient(c, gate.actor, clientId))) {
    return c.json({ error: "client_not_found" }, 404);
  }

  const input = await readJson<ClientTrustInput>(c.req.raw);
  if (!input) {
    return c.json({ error: "invalid_request" }, 400);
  }

  const row = await c.env.PG72_ID_DB.prepare(
    `SELECT clientId, tos, policy, metadata
       FROM oauthClient
      WHERE clientId = ?
      LIMIT 1`,
  )
    .bind(clientId)
    .first<{
      clientId: string;
      tos: string | null;
      policy: string | null;
      metadata: string | null;
    }>();
  if (!row) {
    return c.json({ error: "client_not_found" }, 404);
  }

  // Preserve unrelated metadata keys (e.g. the diary client stores its
  // backchannel_logout_uri here); only developer_name is managed by this
  // endpoint.
  const metadata = parseClientMetadataRecord(row.metadata);
  let developerName = developerNameFromMetadata(metadata);
  if (input.developerName !== undefined) {
    if (!validDeveloperName(input.developerName)) {
      return c.json({ error: "invalid_developer_name" }, 400);
    }
    developerName = input.developerName.trim();
  }
  // The developer identity is mandatory; legacy rows without one must be
  // backfilled through this endpoint and can never be cleared.
  if (!developerName) {
    return c.json({ error: "invalid_developer_name" }, 400);
  }
  metadata[DEVELOPER_NAME_METADATA_KEY] = developerName;

  let termsOfServiceUrl = trustUrlOrNull(row.tos);
  if (input.termsOfServiceUrl !== undefined) {
    const parsed = optionalTrustUrl(input.termsOfServiceUrl);
    if (!parsed.ok) {
      return c.json({ error: "invalid_terms_of_service_url" }, 400);
    }
    termsOfServiceUrl = parsed.url;
  }

  let privacyPolicyUrl = trustUrlOrNull(row.policy);
  if (input.privacyPolicyUrl !== undefined) {
    const parsed = optionalTrustUrl(input.privacyPolicyUrl);
    if (!parsed.ok) {
      return c.json({ error: "invalid_privacy_policy_url" }, 400);
    }
    privacyPolicyUrl = parsed.url;
  }

  const now = new Date().toISOString();
  const update = await c.env.PG72_ID_DB.prepare(
    `UPDATE oauthClient
        SET metadata = ?, tos = ?, policy = ?, updatedAt = ?
      WHERE clientId = ?`,
  )
    .bind(
      JSON.stringify(metadata),
      termsOfServiceUrl,
      privacyPolicyUrl,
      now,
      clientId,
    )
    .run();
  if (update.meta.changes !== 1) {
    return c.json({ error: "client_not_found" }, 404);
  }

  await auditClientChange(
    c,
    "oauth_client.trust_updated",
    clientId,
    gate.actor.userId,
  );

  return c.json({
    clientId,
    developerName,
    privacyPolicyUrl,
    termsOfServiceUrl,
    updatedAt: now,
  });
});

adminClientRoutes.post("/:clientId/rotate-secret", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage");
  if (!gate.ok) return gate.response;

  const clientId = c.req.param("clientId");
  if (!CLIENT_ID_PATTERN.test(clientId)) {
    return c.json({ error: "invalid_client_id" }, 400);
  }
  if (TRUSTED_CLIENT_IDS.has(clientId)) {
    return c.json({ error: "trusted_client_locked" }, 409);
  }
  if (!(await loadManagedClient(c, gate.actor, clientId))) {
    return c.json({ error: "client_not_found" }, 404);
  }

  const client = await c.env.PG72_ID_DB.prepare(
    `SELECT clientId, public, clientSecret
       FROM oauthClient
      WHERE clientId = ?
      LIMIT 1`,
  )
    .bind(clientId)
    .first<{ clientId: string; public: number | null; clientSecret: string | null }>();
  if (!client) {
    return c.json({ error: "client_not_found" }, 404);
  }
  if (client.public === 1 || !client.clientSecret) {
    return c.json({ error: "public_client_has_no_secret" }, 400);
  }

  const clientSecretSuffix = generateClientSecretSuffix();
  const storedClientSecret = await hashClientSecretSuffix(clientSecretSuffix);
  const now = new Date().toISOString();
  const update = await c.env.PG72_ID_DB.prepare(
    "UPDATE oauthClient SET clientSecret = ?, updatedAt = ? WHERE clientId = ?",
  )
    .bind(storedClientSecret, now, clientId)
    .run();
  if (update.meta.changes !== 1) {
    return c.json({ error: "client_not_found" }, 404);
  }

  await auditClientChange(
    c,
    "oauth_client.secret_rotated",
    clientId,
    gate.actor.userId,
  );

  return c.json({
    clientId,
    // The plaintext secret is returned exactly once and never stored.
    clientSecret: `${CLIENT_SECRET_PREFIX}${clientSecretSuffix}`,
    rotatedAt: now,
  });
});

adminClientRoutes.post("/:clientId/status", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage");
  if (!gate.ok) return gate.response;

  const clientId = c.req.param("clientId");
  const input = await readJson<ClientStatusInput>(c.req.raw);
  if (!CLIENT_ID_PATTERN.test(clientId) || typeof input?.disabled !== "boolean") {
    return c.json({ error: "invalid_request" }, 400);
  }
  if (TRUSTED_CLIENT_IDS.has(clientId)) {
    return c.json({ error: "trusted_client_locked" }, 409);
  }
  if (!(await loadManagedClient(c, gate.actor, clientId))) {
    return c.json({ error: "client_not_found" }, 404);
  }

  const now = new Date().toISOString();
  const statements = [
    c.env.PG72_ID_DB.prepare(
      "UPDATE oauthClient SET disabled = ?, updatedAt = ? WHERE clientId = ?",
    ).bind(input.disabled ? 1 : 0, now, clientId),
  ];
  if (input.disabled) {
    // Disabling immediately cuts off issued credentials: access tokens are
    // deleted, refresh tokens are revoked, and pending authorization codes
    // are purged. Consents are kept so re-enabling does not force re-consent.
    statements.push(
      c.env.PG72_ID_DB.prepare(
        "DELETE FROM oauthAccessToken WHERE clientId = ?",
      ).bind(clientId),
      c.env.PG72_ID_DB.prepare(
        "UPDATE oauthRefreshToken SET revoked = ? WHERE clientId = ? AND revoked IS NULL",
      ).bind(now, clientId),
      pendingAuthorizationCodeCleanup(c.env, clientId),
    );
  }

  const results = await c.env.PG72_ID_DB.batch(statements);
  if (results[0]?.meta.changes !== 1) {
    return c.json({ error: "client_not_found" }, 404);
  }

  await auditClientChange(
    c,
    input.disabled ? "oauth_client.disabled" : "oauth_client.enabled",
    clientId,
    gate.actor.userId,
  );

  return c.json({ clientId, disabled: input.disabled, at: now });
});

adminClientRoutes.delete("/:clientId", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage");
  if (!gate.ok) return gate.response;

  const clientId = c.req.param("clientId");
  if (!CLIENT_ID_PATTERN.test(clientId)) {
    return c.json({ error: "invalid_client_id" }, 400);
  }
  if (TRUSTED_CLIENT_IDS.has(clientId)) {
    return c.json({ error: "trusted_client_locked" }, 409);
  }
  if (!(await loadManagedClient(c, gate.actor, clientId))) {
    return c.json({ error: "client_not_found" }, 404);
  }

  // Deleting the client cascades to oauthAccessToken, oauthRefreshToken and
  // oauthConsent via foreign keys; pending authorization codes live in the
  // verification table and are purged explicitly.
  const results = await c.env.PG72_ID_DB.batch([
    pendingAuthorizationCodeCleanup(c.env, clientId),
    c.env.PG72_ID_DB.prepare(
      "DELETE FROM oauthClient WHERE clientId = ?",
    ).bind(clientId),
  ]);
  // meta.changes includes rows removed by ON DELETE CASCADE, so only a zero
  // count means the client did not exist.
  if (!results[1]?.meta.changes) {
    return c.json({ error: "client_not_found" }, 404);
  }

  await auditClientChange(
    c,
    "oauth_client.deleted",
    clientId,
    gate.actor.userId,
  );

  return c.json({ deleted: true, clientId });
});
