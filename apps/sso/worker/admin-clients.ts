import { Hono, type Context } from "hono";

import {
  ADMIN_ACTOR_COMMIT_PREDICATE,
  adminActorCommitBindings,
  type AdminActorCommitGuard,
} from "./admin-commit";
import { requireAdminPermission, type AdminActor } from "./admin-gate";
import {
  auditEventMutationCommitted,
  auditInsertForExistingClientStatement,
  createAuditEvent,
  enqueueSecurityEvent,
  type SecurityEvent,
} from "./audit";
import {
  BACKCHANNEL_LOGOUT_URI_METADATA_KEY,
  DEVELOPER_NAME_METADATA_KEY,
  developerNameFromMetadata,
  parseClientMetadataRecord,
  trustUrlOrNull,
  validDeveloperName,
} from "./client-metadata";
import {
  CLIENT_SECRET_PREFIX,
  MAIL_INTROSPECTION_CLIENT_ID,
  SYSTEM_RESERVED_CLIENT_IDS,
  TRUSTED_CLIENT_IDS,
  WEBMAIL_CLIENT_ID,
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
const INTROSPECTION_ONLY_GRANT = "urn:pg72:grant-type:introspection-only";

interface CreateClientInput {
  backchannelLogoutUri?: unknown;
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
  backchannelLogoutUri?: unknown;
  developerName?: unknown;
  privacyPolicyUrl?: unknown;
  termsOfServiceUrl?: unknown;
}

interface UpdateClientInput extends ClientTrustInput {
  enableEndSession?: unknown;
  expectedUpdatedAt?: unknown;
  grantTypes?: unknown;
  name?: unknown;
  postLogoutRedirectUris?: unknown;
  redirectUris?: unknown;
  scopes?: unknown;
  uri?: unknown;
}

const CLIENT_UPDATE_FIELDS = new Set([
  "backchannelLogoutUri",
  "developerName",
  "enableEndSession",
  "expectedUpdatedAt",
  "grantTypes",
  "name",
  "postLogoutRedirectUris",
  "privacyPolicyUrl",
  "redirectUris",
  "scopes",
  "termsOfServiceUrl",
  "uri",
]);

interface AdminClientRow {
  backchannelLogoutUri: string | null;
  clientId: string;
  enableEndSession: number | null;
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

interface ManagedClientRow {
  backchannelLogoutUri: string | null;
  enableEndSession: number | null;
  grantTypes: string | null;
  id: string;
  name: string | null;
  ownerUserId: string | null;
  postLogoutRedirectUris: string | null;
  public: number | null;
  redirectUris: string;
  clientSecret: string | null;
  scopes: string | null;
  tos: string | null;
  policy: string | null;
  metadata: string | null;
  uri: string | null;
  updatedAt: string | null;
}

interface ManagedClientGuard {
  actor: AdminActorCommitGuard;
  authorizationEventId?: string;
  clientId: string;
  clientRowId: string;
  expectedOwnerUserId?: string;
  expectedUpdatedAt?: string | null;
}

// Before the guarded success audit exists, every statement revalidates the
// actor/session. Later statements in that same D1 batch use the exact audit ID
// as the transaction-local authorization snapshot, matching the repository's
// established admin/recovery mutation pattern.
const MANAGED_CLIENT_PREDICATE = `id = ?
  AND clientId = ?
  AND (? IS NULL OR ownerUserId = ?)
  AND (? = 0 OR updatedAt IS ?)
  AND (? IS NULL OR EXISTS (SELECT 1 FROM audit_event WHERE id = ?))
  AND (? IS NOT NULL OR ${ADMIN_ACTOR_COMMIT_PREDICATE})`;

function managedClientGuardBindings(guard: ManagedClientGuard): unknown[] {
  return [
    guard.clientRowId,
    guard.clientId,
    guard.expectedOwnerUserId ?? null,
    guard.expectedOwnerUserId ?? null,
    guard.expectedUpdatedAt === undefined ? 0 : 1,
    guard.expectedUpdatedAt ?? null,
    guard.authorizationEventId ?? null,
    guard.authorizationEventId ?? null,
    guard.authorizationEventId ?? null,
    ...adminActorCommitBindings(guard.actor),
  ];
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

function validBackchannelLogoutUri(
  value: unknown,
  environment: RuntimeConfig["environment"],
): value is string {
  if (!validRedirectUri(value, environment) || value.includes("@")) {
    return false;
  }
  const url = new URL(value);
  return url.protocol === "https:" || url.port.length > 0;
}

function validStringArray(
  value: unknown,
  maxCount: number,
): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= maxCount &&
    value.every((entry) => typeof entry === "string") &&
    new Set(value).size === value.length
  );
}

function sameStringSet(left: string[], right: string[]): boolean {
  return (
    left.length === right.length &&
    left.every((entry) => right.includes(entry))
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
    backchannelLogoutUri: row.backchannelLogoutUri,
    uri: row.uri,
    disabled: row.disabled === 1,
    enableEndSession: row.enableEndSession === 1,
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
function pendingAuthorizationCodeCleanup(
  env: Env,
  guard: ManagedClientGuard,
) {
  return env.PG72_ID_DB.prepare(
    `DELETE FROM verification
      WHERE CASE WHEN json_valid(value) THEN
        json_extract(value, '$.type') = 'authorization_code'
        AND json_extract(value, '$.query.client_id') = ?
      ELSE 0 END
        AND EXISTS (
          SELECT 1
            FROM oauthClient
           WHERE ${MANAGED_CLIENT_PREDICATE}
        )`,
  ).bind(guard.clientId, ...managedClientGuardBindings(guard));
}

function clientConsentCleanup(env: Env, guard: ManagedClientGuard) {
  return env.PG72_ID_DB.prepare(
    `DELETE FROM oauthConsent
      WHERE clientId = ?
        AND EXISTS (
          SELECT 1
            FROM oauthClient
           WHERE ${MANAGED_CLIENT_PREDICATE}
        )`,
  ).bind(guard.clientId, ...managedClientGuardBindings(guard));
}

function clientAccessTokenCleanup(env: Env, guard: ManagedClientGuard) {
  return env.PG72_ID_DB.prepare(
    `DELETE FROM oauthAccessToken
      WHERE clientId = ?
        AND EXISTS (
          SELECT 1
            FROM oauthClient
           WHERE ${MANAGED_CLIENT_PREDICATE}
        )`,
  ).bind(guard.clientId, ...managedClientGuardBindings(guard));
}

function clientRefreshTokenRevocation(
  env: Env,
  guard: ManagedClientGuard,
  revokedAt: string,
) {
  return env.PG72_ID_DB.prepare(
    `UPDATE oauthRefreshToken
        SET revoked = ?
      WHERE clientId = ?
        AND revoked IS NULL
        AND EXISTS (
          SELECT 1
            FROM oauthClient
           WHERE ${MANAGED_CLIENT_PREDICATE}
        )`,
  ).bind(
    revokedAt,
    guard.clientId,
    ...managedClientGuardBindings(guard),
  );
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
): Promise<ManagedClientRow | null> {
  const row = await c.env.PG72_ID_DB.prepare(
    `SELECT id, ownerUserId, public, clientSecret, tos, policy, metadata,
            backchannelLogoutUri, name, uri, redirectUris,
            postLogoutRedirectUris, scopes, grantTypes, enableEndSession,
            updatedAt
       FROM oauthClient
      WHERE clientId = ?
      LIMIT 1`,
  )
    .bind(clientId)
    .first<ManagedClientRow>();
  if (!row) return null;
  if (SYSTEM_RESERVED_CLIENT_IDS.has(clientId) && !managesAllClients(actor)) {
    return null;
  }
  if (!managesAllClients(actor) && row.ownerUserId !== actor.userId) {
    return null;
  }
  return row;
}

function mutationGuard(
  actor: AdminActor,
  clientId: string,
  client: ManagedClientRow,
): ManagedClientGuard {
  return {
    actor: actor.commitGuard,
    clientId,
    clientRowId: client.id,
    // Developers must still own the exact row when the batch executes.
    // Admins may manage ownership changes, but never a replacement row.
    ...(managesAllClients(actor)
      ? {}
      : { expectedOwnerUserId: client.ownerUserId ?? actor.userId }),
  };
}

function clientAuditEvent(
  eventType: string,
  clientId: string,
  adminUserId: string,
): SecurityEvent {
  return createAuditEvent({
    eventType,
    outcome: "success",
    clientId,
    subjectId: adminUserId,
    actorUserId: adminUserId,
  });
}

export const adminClientRoutes = new Hono<AppEnv>();

adminClientRoutes.get("/", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage");
  if (!gate.ok) return gate.response;

  // Developers only see clients they own; admin/bootadmin see everything,
  // including unowned (NULL owner) clients such as the seeded first-party
  // relying parties.
  const result = await c.env.PG72_ID_DB.prepare(
    `SELECT clientId, name, uri, disabled, enableEndSession, public, scopes, redirectUris,
            postLogoutRedirectUris, grantTypes, tokenEndpointAuthMethod,
            tos, policy, metadata, backchannelLogoutUri,
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

adminClientRoutes.post("/provision-mail-introspector", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage_all", {
    fresh: true,
    passkeyStepUp: true,
  });
  if (!gate.ok) return gate.response;

  const existing = await c.env.PG72_ID_DB.prepare(
    "SELECT clientId FROM oauthClient WHERE clientId = ? LIMIT 1",
  )
    .bind(MAIL_INTROSPECTION_CLIENT_ID)
    .first();
  if (existing) {
    return c.json({ error: "client_exists" }, 409);
  }

  const clientSecretSuffix = generateClientSecretSuffix();
  const storedClientSecret = await hashClientSecretSuffix(clientSecretSuffix);
  const clientRowId = crypto.randomUUID();
  const now = new Date().toISOString();
  const metadata = {
    [DEVELOPER_NAME_METADATA_KEY]: "PG72 Mail Infrastructure",
    introspectionTargetClientId: WEBMAIL_CLIENT_ID,
    purpose: "mail-token-introspection",
  };
  const auditEvent = clientAuditEvent(
    "oauth_client.created",
    MAIL_INTROSPECTION_CLIENT_ID,
    gate.actor.userId,
  );

  try {
    const results = await c.env.PG72_ID_DB.batch([
      c.env.PG72_ID_DB.prepare(
        `INSERT INTO oauthClient (
          id, clientId, clientSecret, disabled, skipConsent, enableEndSession,
          subjectType, scopes, createdAt, updatedAt, name, redirectUris,
          postLogoutRedirectUris, tokenEndpointAuthMethod, grantTypes,
          responseTypes, public, type, requirePKCE, ownerUserId, metadata
        ) SELECT ?, ?, ?, 0, 0, 0, 'public', '[]', ?, ?, ?, '[]', NULL,
                 'client_secret_post', ?, '[]', 0, 'service', 1, ?, ?
            WHERE ${ADMIN_ACTOR_COMMIT_PREDICATE}`,
      ).bind(
          clientRowId,
          MAIL_INTROSPECTION_CLIENT_ID,
          storedClientSecret,
          now,
          now,
          "PGID Mail Token Introspection",
          JSON.stringify([INTROSPECTION_ONLY_GRANT]),
          null,
          JSON.stringify(metadata),
          ...adminActorCommitBindings(gate.actor.commitGuard),
        ),
      auditInsertForExistingClientStatement(c.env, auditEvent, {
        actor: gate.actor.commitGuard,
        clientId: MAIL_INTROSPECTION_CLIENT_ID,
        clientRowId,
      }),
    ]);
    if (
      results[0]?.meta.changes !== 1 ||
      !auditEventMutationCommitted(results[1])
    ) {
      return c.json({ error: "management_state_changed" }, 409);
    }
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.includes("UNIQUE constraint failed")
    ) {
      return c.json({ error: "client_exists" }, 409);
    }
    throw error;
  }

  await enqueueSecurityEvent(c.env, auditEvent, c.executionCtx);

  return c.json(
    {
      client: {
        backchannelLogoutUri: null,
        clientId: MAIL_INTROSPECTION_CLIENT_ID,
        name: "PGID Mail Token Introspection",
        disabled: false,
        enableEndSession: false,
        public: false,
        scopes: [],
        redirectUris: [],
        postLogoutRedirectUris: [],
        grantTypes: [INTROSPECTION_ONLY_GRANT],
        tokenEndpointAuthMethod: "client_secret_post",
        hasSecret: true,
        trusted: false,
        ownerUserId: null,
        createdAt: now,
        updatedAt: now,
      },
      // The plaintext secret is returned exactly once and never stored.
      clientSecret: `${CLIENT_SECRET_PREFIX}${clientSecretSuffix}`,
    },
    201,
  );
});

adminClientRoutes.post("/", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage", {
    fresh: true,
    passkeyStepUp: true,
  });
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
  if (clientId === MAIL_INTROSPECTION_CLIENT_ID) {
    return c.json({ error: "system_client_requires_provisioning" }, 409);
  }
  if (
    SYSTEM_RESERVED_CLIENT_IDS.has(clientId) &&
    !managesAllClients(gate.actor)
  ) {
    return c.json({ error: "reserved_client_id" }, 403);
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

  let backchannelLogoutUri: string | null = null;
  if (
    input.backchannelLogoutUri !== undefined &&
    input.backchannelLogoutUri !== null &&
    input.backchannelLogoutUri !== ""
  ) {
    if (
      !validBackchannelLogoutUri(
        input.backchannelLogoutUri,
        config.environment,
      )
    ) {
      return c.json({ error: "invalid_backchannel_logout_uri" }, 400);
    }
    backchannelLogoutUri = input.backchannelLogoutUri;
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
  const clientRowId = crypto.randomUUID();
  const now = new Date().toISOString();
  const ownerUserId = SYSTEM_RESERVED_CLIENT_IDS.has(clientId)
    ? null
    : gate.actor.userId;
  const auditEvent = clientAuditEvent(
    "oauth_client.created",
    clientId,
    gate.actor.userId,
  );
  const metadata = {
    [DEVELOPER_NAME_METADATA_KEY]: developerName,
    ...(backchannelLogoutUri
      ? { [BACKCHANNEL_LOGOUT_URI_METADATA_KEY]: backchannelLogoutUri }
      : {}),
  };

  try {
    const results = await c.env.PG72_ID_DB.batch([
      c.env.PG72_ID_DB.prepare(
        `INSERT INTO oauthClient (
          id, clientId, clientSecret, disabled, skipConsent, enableEndSession,
          subjectType, scopes, createdAt, updatedAt, name, uri, redirectUris,
          postLogoutRedirectUris, tokenEndpointAuthMethod, grantTypes,
          responseTypes, public, type, requirePKCE, ownerUserId, tos, policy,
          metadata, backchannelLogoutUri
        ) SELECT ?, ?, ?, 0, 0, ?, 'public', ?, ?, ?, ?, ?, ?, ?, ?, ?, '["code"]', ?, ?, 1, ?, ?, ?, ?, ?
            WHERE ${ADMIN_ACTOR_COMMIT_PREDICATE}`,
      ).bind(
          clientRowId,
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
          ownerUserId,
          termsOfService.url,
          privacyPolicy.url,
          JSON.stringify(metadata),
          backchannelLogoutUri,
          ...adminActorCommitBindings(gate.actor.commitGuard),
        ),
      auditInsertForExistingClientStatement(c.env, auditEvent, {
        actor: gate.actor.commitGuard,
        clientId,
        clientRowId,
        ...(ownerUserId ? { expectedOwnerUserId: ownerUserId } : {}),
      }),
    ]);
    if (
      results[0]?.meta.changes !== 1 ||
      !auditEventMutationCommitted(results[1])
    ) {
      return c.json({ error: "management_state_changed" }, 409);
    }
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.includes("UNIQUE constraint failed")
    ) {
      return c.json({ error: "client_exists" }, 409);
    }
    throw error;
  }

  await enqueueSecurityEvent(c.env, auditEvent, c.executionCtx);

  return c.json(
    {
      client: {
        clientId,
        name,
        developerName,
        privacyPolicyUrl: privacyPolicy.url,
        termsOfServiceUrl: termsOfService.url,
        backchannelLogoutUri,
        uri,
        disabled: false,
        enableEndSession,
        public: isPublic,
        scopes,
        redirectUris,
        postLogoutRedirectUris,
        grantTypes,
        tokenEndpointAuthMethod,
        hasSecret: !isPublic,
        trusted: false,
        ownerUserId,
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
  const gate = await requireAdminPermission(c, "clients.manage", {
    fresh: true,
    passkeyStepUp: true,
  });
  if (!gate.ok) return gate.response;

  const clientId = c.req.param("clientId");
  if (!CLIENT_ID_PATTERN.test(clientId)) {
    return c.json({ error: "invalid_client_id" }, 400);
  }
  if (TRUSTED_CLIENT_IDS.has(clientId)) {
    return c.json({ error: "trusted_client_locked" }, 409);
  }
  // Same ownership rule as every other mutation: developers may only edit
  // clients they own (404 keeps client IDs private).
  const managedClient = await loadManagedClient(c, gate.actor, clientId);
  if (!managedClient) {
    return c.json({ error: "client_not_found" }, 404);
  }
  const rawInput = await readJson<unknown>(c.req.raw);
  if (
    !rawInput ||
    typeof rawInput !== "object" ||
    Array.isArray(rawInput)
  ) {
    return c.json({ error: "invalid_request" }, 400);
  }
  const inputFields = Object.keys(rawInput);
  const mutationFields = inputFields.filter(
    (field) => field !== "expectedUpdatedAt",
  );
  if (
    mutationFields.length === 0 ||
    inputFields.some((field) => !CLIENT_UPDATE_FIELDS.has(field))
  ) {
    return c.json({ error: "invalid_client_update" }, 400);
  }
  const input = rawInput as UpdateClientInput;
  if (
    !Object.prototype.hasOwnProperty.call(rawInput, "expectedUpdatedAt") ||
    (input.expectedUpdatedAt !== null &&
      (typeof input.expectedUpdatedAt !== "string" ||
        input.expectedUpdatedAt.length === 0 ||
        input.expectedUpdatedAt.length > 64))
  ) {
    return c.json({ error: "invalid_client_version" }, 400);
  }
  if (input.expectedUpdatedAt !== managedClient.updatedAt) {
    return c.json({ error: "management_state_changed" }, 409);
  }
  const versionGuard: ManagedClientGuard = {
    ...mutationGuard(gate.actor, clientId, managedClient),
    expectedUpdatedAt: input.expectedUpdatedAt,
  };

  const authorizationFieldUpdate = mutationFields.some((field) =>
    [
      "enableEndSession",
      "grantTypes",
      "postLogoutRedirectUris",
      "redirectUris",
      "scopes",
    ].includes(field),
  );
  if (
    clientId === MAIL_INTROSPECTION_CLIENT_ID &&
    authorizationFieldUpdate
  ) {
    return c.json({ error: "system_client_protocol_locked" }, 409);
  }

  const config = readRuntimeConfig(c.env);

  let name = managedClient.name;
  if (input.name !== undefined) {
    if (typeof input.name !== "string") {
      return c.json({ error: "invalid_client_name" }, 400);
    }
    const nextName = input.name.trim();
    if (!nextName || nextName.length > CLIENT_NAME_MAX_LENGTH) {
      return c.json({ error: "invalid_client_name" }, 400);
    }
    name = nextName;
  }

  let uri = managedClient.uri;
  if (input.uri !== undefined) {
    if (input.uri === null || input.uri === "") {
      uri = null;
    } else if (
      typeof input.uri === "string" &&
      input.uri.length <= CLIENT_URI_MAX_LENGTH &&
      validRedirectUri(input.uri, config.environment)
    ) {
      uri = input.uri;
    } else {
      return c.json({ error: "invalid_client_uri" }, 400);
    }
  }

  const currentRedirectUris = parseJsonStringArray(managedClient.redirectUris);
  let redirectUris = currentRedirectUris;
  let redirectUrisStorage = managedClient.redirectUris;
  if (input.redirectUris !== undefined) {
    if (
      !validStringArray(input.redirectUris, REDIRECT_URI_MAX_COUNT) ||
      input.redirectUris.length === 0 ||
      !input.redirectUris.every((redirectUri) =>
        validRedirectUri(redirectUri, config.environment),
      )
    ) {
      return c.json({ error: "invalid_redirect_uri" }, 400);
    }
    redirectUris = input.redirectUris;
    redirectUrisStorage = JSON.stringify(redirectUris);
  }

  const currentPostLogoutRedirectUris = parseJsonStringArray(
    managedClient.postLogoutRedirectUris,
  );
  let postLogoutRedirectUris = currentPostLogoutRedirectUris;
  let postLogoutRedirectUrisStorage = managedClient.postLogoutRedirectUris;
  if (input.postLogoutRedirectUris !== undefined) {
    if (
      !validStringArray(
        input.postLogoutRedirectUris,
        REDIRECT_URI_MAX_COUNT,
      ) ||
      !input.postLogoutRedirectUris.every((redirectUri) =>
        validRedirectUri(redirectUri, config.environment),
      )
    ) {
      return c.json({ error: "invalid_post_logout_redirect_uri" }, 400);
    }
    postLogoutRedirectUris = input.postLogoutRedirectUris;
    postLogoutRedirectUrisStorage = postLogoutRedirectUris.length
      ? JSON.stringify(postLogoutRedirectUris)
      : null;
  }

  const currentScopes = parseJsonStringArray(managedClient.scopes);
  let scopes = currentScopes;
  let scopesStorage = managedClient.scopes;
  if (input.scopes !== undefined) {
    if (
      !validStringArray(input.scopes, ALLOWED_SCOPES.size) ||
      input.scopes.length === 0 ||
      !input.scopes.every((scope) => ALLOWED_SCOPES.has(scope)) ||
      !input.scopes.includes("openid")
    ) {
      return c.json({ error: "invalid_scopes" }, 400);
    }
    scopes = input.scopes;
    scopesStorage = JSON.stringify(scopes);
  }

  const currentGrantTypes = parseJsonStringArray(managedClient.grantTypes);
  let grantTypes = currentGrantTypes;
  let grantTypesStorage = managedClient.grantTypes;
  if (input.grantTypes !== undefined) {
    if (
      !validStringArray(input.grantTypes, ALLOWED_GRANT_TYPES.size) ||
      !input.grantTypes.every((grant) => ALLOWED_GRANT_TYPES.has(grant)) ||
      !input.grantTypes.includes("authorization_code")
    ) {
      return c.json({ error: "invalid_grant_types" }, 400);
    }
    grantTypes = input.grantTypes;
    grantTypesStorage = JSON.stringify(grantTypes);
  }
  if (
    (input.scopes !== undefined || input.grantTypes !== undefined) &&
    grantTypes.includes("refresh_token") &&
    !scopes.includes("offline_access")
  ) {
    return c.json({ error: "refresh_token_requires_offline_access" }, 400);
  }

  let enableEndSession = managedClient.enableEndSession === 1;
  let enableEndSessionStorage = managedClient.enableEndSession;
  if (input.enableEndSession !== undefined) {
    if (typeof input.enableEndSession !== "boolean") {
      return c.json({ error: "invalid_request" }, 400);
    }
    enableEndSession = input.enableEndSession;
    enableEndSessionStorage = enableEndSession ? 1 : 0;
  }

  // Preserve unrelated provider metadata while keeping the interoperable JSON
  // key in sync with the validated dedicated delivery column.
  const metadata = parseClientMetadataRecord(managedClient.metadata);
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

  let backchannelLogoutUri = managedClient.backchannelLogoutUri;
  if (input.backchannelLogoutUri !== undefined) {
    if (
      input.backchannelLogoutUri === null ||
      input.backchannelLogoutUri === ""
    ) {
      backchannelLogoutUri = null;
      delete metadata[BACKCHANNEL_LOGOUT_URI_METADATA_KEY];
    } else if (
      validBackchannelLogoutUri(input.backchannelLogoutUri, config.environment)
    ) {
      backchannelLogoutUri = input.backchannelLogoutUri;
      metadata[BACKCHANNEL_LOGOUT_URI_METADATA_KEY] = backchannelLogoutUri;
    } else {
      return c.json({ error: "invalid_backchannel_logout_uri" }, 400);
    }
  }

  let termsOfServiceUrl = trustUrlOrNull(managedClient.tos);
  if (input.termsOfServiceUrl !== undefined) {
    const parsed = optionalTrustUrl(input.termsOfServiceUrl);
    if (!parsed.ok) {
      return c.json({ error: "invalid_terms_of_service_url" }, 400);
    }
    termsOfServiceUrl = parsed.url;
  }

  let privacyPolicyUrl = trustUrlOrNull(managedClient.policy);
  if (input.privacyPolicyUrl !== undefined) {
    const parsed = optionalTrustUrl(input.privacyPolicyUrl);
    if (!parsed.ok) {
      return c.json({ error: "invalid_privacy_policy_url" }, 400);
    }
    privacyPolicyUrl = parsed.url;
  }

  let now = new Date().toISOString();
  if (now === input.expectedUpdatedAt) {
    now = new Date(Date.now() + 1).toISOString();
  }
  const redirectUrisChanged = !sameStringSet(
    currentRedirectUris,
    redirectUris,
  );
  const permissionsChanged =
    !sameStringSet(currentScopes, scopes) ||
    !sameStringSet(currentGrantTypes, grantTypes);
  const settingsUpdated = mutationFields.some((field) =>
    [
      "enableEndSession",
      "grantTypes",
      "name",
      "postLogoutRedirectUris",
      "redirectUris",
      "scopes",
      "uri",
    ].includes(field),
  );
  const auditEvent = clientAuditEvent(
    settingsUpdated ? "oauth_client.updated" : "oauth_client.trust_updated",
    clientId,
    gate.actor.userId,
  );
  const commitGuard: ManagedClientGuard = {
    ...versionGuard,
    authorizationEventId: auditEvent.eventId,
  };
  const update = c.env.PG72_ID_DB.prepare(
    `UPDATE oauthClient
        SET name = ?, uri = ?, redirectUris = ?, postLogoutRedirectUris = ?,
            scopes = ?, grantTypes = ?, enableEndSession = ?, metadata = ?,
            tos = ?, policy = ?, backchannelLogoutUri = ?, updatedAt = ?
      WHERE ${MANAGED_CLIENT_PREDICATE}`,
  )
    .bind(
      name,
      uri,
      redirectUrisStorage,
      postLogoutRedirectUrisStorage,
      scopesStorage,
      grantTypesStorage,
      enableEndSessionStorage,
      JSON.stringify(metadata),
      termsOfServiceUrl,
      privacyPolicyUrl,
      backchannelLogoutUri,
      now,
      ...managedClientGuardBindings(commitGuard),
    );
  const statements = [
    auditInsertForExistingClientStatement(c.env, auditEvent, versionGuard),
  ];
  if (redirectUrisChanged || permissionsChanged) {
    statements.push(
      pendingAuthorizationCodeCleanup(c.env, commitGuard),
      clientConsentCleanup(c.env, commitGuard),
    );
  }
  if (permissionsChanged) {
    statements.push(
      clientAccessTokenCleanup(c.env, commitGuard),
      clientRefreshTokenRevocation(c.env, commitGuard, now),
    );
  }
  const updateStatementIndex = statements.length;
  statements.push(update);
  const results = await c.env.PG72_ID_DB.batch(statements);
  // Preserve the deliberate tolerance for other transaction-local audit
  // triggers while requiring both the audit row and its archive-source row.
  if (
    (results[0]?.meta.changes ?? 0) < 2 ||
    results[updateStatementIndex]?.meta.changes !== 1
  ) {
    return c.json({ error: "management_state_changed" }, 409);
  }
  await enqueueSecurityEvent(c.env, auditEvent, c.executionCtx);

  return c.json({
    clientId,
    name: name ?? clientId,
    developerName,
    privacyPolicyUrl,
    termsOfServiceUrl,
    backchannelLogoutUri,
    uri,
    redirectUris,
    postLogoutRedirectUris,
    scopes,
    grantTypes,
    enableEndSession,
    updatedAt: now,
  });
});

adminClientRoutes.post("/:clientId/rotate-secret", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage", {
    fresh: true,
    passkeyStepUp: true,
  });
  if (!gate.ok) return gate.response;

  const clientId = c.req.param("clientId");
  if (!CLIENT_ID_PATTERN.test(clientId)) {
    return c.json({ error: "invalid_client_id" }, 400);
  }
  if (TRUSTED_CLIENT_IDS.has(clientId)) {
    return c.json({ error: "trusted_client_locked" }, 409);
  }
  const managedClient = await loadManagedClient(c, gate.actor, clientId);
  if (!managedClient) {
    return c.json({ error: "client_not_found" }, 404);
  }
  const guard = mutationGuard(gate.actor, clientId, managedClient);
  if (managedClient.public === 1 || !managedClient.clientSecret) {
    return c.json({ error: "public_client_has_no_secret" }, 400);
  }

  const clientSecretSuffix = generateClientSecretSuffix();
  const storedClientSecret = await hashClientSecretSuffix(clientSecretSuffix);
  const now = new Date().toISOString();
  const update = c.env.PG72_ID_DB.prepare(
    `UPDATE oauthClient
        SET clientSecret = ?, updatedAt = ?
      WHERE ${MANAGED_CLIENT_PREDICATE}`,
  )
    .bind(storedClientSecret, now, ...managedClientGuardBindings(guard));
  const auditEvent = clientAuditEvent(
    "oauth_client.secret_rotated",
    clientId,
    gate.actor.userId,
  );
  const results = await c.env.PG72_ID_DB.batch([
    update,
    auditInsertForExistingClientStatement(c.env, auditEvent, guard),
  ]);
  if (
    results[0]?.meta.changes !== 1 ||
    !auditEventMutationCommitted(results[1])
  ) {
    return c.json({ error: "management_state_changed" }, 409);
  }
  await enqueueSecurityEvent(c.env, auditEvent, c.executionCtx);

  return c.json({
    clientId,
    // The plaintext secret is returned exactly once and never stored.
    clientSecret: `${CLIENT_SECRET_PREFIX}${clientSecretSuffix}`,
    rotatedAt: now,
  });
});

adminClientRoutes.post("/:clientId/status", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage", {
    fresh: true,
    passkeyStepUp: true,
  });
  if (!gate.ok) return gate.response;

  const clientId = c.req.param("clientId");
  const input = await readJson<ClientStatusInput>(c.req.raw);
  if (!CLIENT_ID_PATTERN.test(clientId) || typeof input?.disabled !== "boolean") {
    return c.json({ error: "invalid_request" }, 400);
  }
  if (TRUSTED_CLIENT_IDS.has(clientId)) {
    return c.json({ error: "trusted_client_locked" }, 409);
  }
  const managedClient = await loadManagedClient(c, gate.actor, clientId);
  if (!managedClient) {
    return c.json({ error: "client_not_found" }, 404);
  }
  const guard = mutationGuard(gate.actor, clientId, managedClient);

  const now = new Date().toISOString();
  const statements = [
    c.env.PG72_ID_DB.prepare(
      `UPDATE oauthClient
          SET disabled = ?, updatedAt = ?
        WHERE ${MANAGED_CLIENT_PREDICATE}`,
    ).bind(
      input.disabled ? 1 : 0,
      now,
      ...managedClientGuardBindings(guard),
    ),
  ];
  if (input.disabled) {
    // Disabling immediately cuts off issued credentials: access tokens are
    // deleted, refresh tokens are revoked, and pending authorization codes
    // are purged. Consents are kept so re-enabling does not force re-consent.
    statements.push(
      c.env.PG72_ID_DB.prepare(
        `DELETE FROM oauthAccessToken
          WHERE clientId = ?
            AND EXISTS (
              SELECT 1
                FROM oauthClient
               WHERE ${MANAGED_CLIENT_PREDICATE}
            )`,
      ).bind(clientId, ...managedClientGuardBindings(guard)),
      c.env.PG72_ID_DB.prepare(
        `UPDATE oauthRefreshToken
            SET revoked = ?
          WHERE clientId = ?
            AND revoked IS NULL
            AND EXISTS (
              SELECT 1
                FROM oauthClient
               WHERE ${MANAGED_CLIENT_PREDICATE}
            )`,
      ).bind(now, clientId, ...managedClientGuardBindings(guard)),
      pendingAuthorizationCodeCleanup(c.env, guard),
    );
  }
  const auditEvent = clientAuditEvent(
    input.disabled ? "oauth_client.disabled" : "oauth_client.enabled",
    clientId,
    gate.actor.userId,
  );
  const auditStatementIndex = statements.length;
  statements.push(
    auditInsertForExistingClientStatement(c.env, auditEvent, guard),
  );

  const results = await c.env.PG72_ID_DB.batch(statements);
  if (
    results[0]?.meta.changes !== 1 ||
    !auditEventMutationCommitted(results[auditStatementIndex])
  ) {
    return c.json({ error: "management_state_changed" }, 409);
  }

  await enqueueSecurityEvent(c.env, auditEvent, c.executionCtx);

  return c.json({ clientId, disabled: input.disabled, at: now });
});

adminClientRoutes.delete("/:clientId", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage", {
    fresh: true,
    passkeyStepUp: true,
  });
  if (!gate.ok) return gate.response;

  const clientId = c.req.param("clientId");
  if (!CLIENT_ID_PATTERN.test(clientId)) {
    return c.json({ error: "invalid_client_id" }, 400);
  }
  if (TRUSTED_CLIENT_IDS.has(clientId)) {
    return c.json({ error: "trusted_client_locked" }, 409);
  }
  const managedClient = await loadManagedClient(c, gate.actor, clientId);
  if (!managedClient) {
    return c.json({ error: "client_not_found" }, 404);
  }
  const guard = mutationGuard(gate.actor, clientId, managedClient);

  // Deleting the client cascades to oauthAccessToken, oauthRefreshToken and
  // oauthConsent via foreign keys; pending authorization codes live in the
  // verification table and are purged explicitly.
  const auditEvent = clientAuditEvent(
    "oauth_client.deleted",
    clientId,
    gate.actor.userId,
  );
  const results = await c.env.PG72_ID_DB.batch([
    pendingAuthorizationCodeCleanup(c.env, guard),
    auditInsertForExistingClientStatement(c.env, auditEvent, guard),
    c.env.PG72_ID_DB.prepare(
      `DELETE FROM oauthClient WHERE ${MANAGED_CLIENT_PREDICATE}`,
    ).bind(...managedClientGuardBindings(guard)),
  ]);
  // meta.changes includes rows removed by ON DELETE CASCADE, so only a zero
  // count means the client did not exist.
  if (
    !auditEventMutationCommitted(results[1]) ||
    !results[2]?.meta.changes
  ) {
    return c.json({ error: "management_state_changed" }, 409);
  }

  await enqueueSecurityEvent(c.env, auditEvent, c.executionCtx);

  return c.json({ deleted: true, clientId });
});
