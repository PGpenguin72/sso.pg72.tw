import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  continueCurrentAccountSelection,
  createAuthenticatedUser,
  sha256Base64Url,
} from "./helpers";

const BASE_URL = "http://localhost:5173";
const CLIENT_SECRET_PREFIX = "pg72_cs_";
const OPENID_SCOPES = ["openid", "profile", "email"];
const OFFLINE_SCOPES = [...OPENID_SCOPES, "offline_access"];

interface ClientFixture {
  clientId: string;
  clientSecret: string;
  enableEndSession: boolean;
  postLogoutRedirectUri: string;
  redirectUri: string;
}

interface TokenPayload {
  access_token?: string;
  error?: string;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
  token_type?: string;
}

interface IssuedTokens {
  client: ClientFixture;
  payload: TokenPayload;
  sessionId: string;
  userId: string;
}

interface TokenCounts {
  access_tokens: number;
  refresh_tokens: number;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

function routeJwksFetchThroughWorker(): void {
  vi.stubGlobal(
    "fetch",
    (input: RequestInfo | URL, init?: RequestInit) =>
      exports.default.fetch(
        input instanceof Request && init === undefined
          ? input
          : new Request(input, init),
      ),
  );
}

async function storeClient(options: {
  enableEndSession: boolean;
  refresh?: boolean;
}): Promise<ClientFixture> {
  const clientId = `sid-${crypto.randomUUID()}`;
  const clientSecretSuffix = crypto.randomUUID().replaceAll("-", "");
  const clientSecret = `${CLIENT_SECRET_PREFIX}${clientSecretSuffix}`;
  const redirectUri = `https://${clientId}.example/callback`;
  const postLogoutRedirectUri = `https://${clientId}.example/logout`;
  const now = new Date().toISOString();
  const scopes = options.refresh ? OFFLINE_SCOPES : OPENID_SCOPES;
  const grantTypes = options.refresh
    ? ["authorization_code", "refresh_token"]
    : ["authorization_code"];

  await env.PG72_ID_DB.prepare(
    `INSERT INTO oauthClient (
      id, clientId, clientSecret, disabled, skipConsent, enableEndSession,
      subjectType, scopes, createdAt, updatedAt, name, redirectUris,
      postLogoutRedirectUris, tokenEndpointAuthMethod, grantTypes,
      responseTypes, public, type, requirePKCE
    ) VALUES (?, ?, ?, 0, 0, ?, 'public', ?, ?, ?, ?, ?, ?,
              'client_secret_post', ?, '["code"]', 0, 'web', 1)`,
  )
    .bind(
      crypto.randomUUID(),
      clientId,
      await sha256Base64Url(clientSecretSuffix),
      options.enableEndSession ? 1 : 0,
      JSON.stringify(scopes),
      now,
      now,
      "SID Contract Test Client",
      JSON.stringify([redirectUri]),
      JSON.stringify([postLogoutRedirectUri]),
      JSON.stringify(grantTypes),
    )
    .run();

  return {
    clientId,
    clientSecret,
    enableEndSession: options.enableEndSession,
    postLogoutRedirectUri,
    redirectUri,
  };
}

async function authorize(
  client: ClientFixture,
  user: Awaited<ReturnType<typeof createAuthenticatedUser>>,
  scopes: string[],
): Promise<{ code: string; nonce: string; verifier: string }> {
  const verifier = "sid-contract-verifier-sid-contract-verifier";
  const challenge = await sha256Base64Url(verifier);
  const nonce = crypto.randomUUID();
  const query = new URLSearchParams({
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    response_type: "code",
    scope: scopes.join(" "),
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: crypto.randomUUID(),
    nonce,
  });
  const authorizeResponse = await continueCurrentAccountSelection(
    await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/authorize?${query}`, {
        headers: user.headers,
        redirect: "manual",
      }),
    ),
    user.headers,
    BASE_URL,
  );
  expect(authorizeResponse.status).toBe(302);
  const consentLocation = new URL(
    authorizeResponse.headers.get("location") ?? "",
    BASE_URL,
  );
  expect(consentLocation.pathname).toBe("/consent");

  const consentHeaders = new Headers(user.headers);
  consentHeaders.set("Sec-Fetch-Mode", "cors");
  const consentResponse = await exports.default.fetch(
    new Request(`${BASE_URL}/oauth2/consent`, {
      method: "POST",
      headers: consentHeaders,
      body: JSON.stringify({
        accept: true,
        oauth_query: consentLocation.search.slice(1),
      }),
    }),
  );
  expect(consentResponse.status).toBe(200);
  const consent = (await consentResponse.json()) as { url?: string };
  const code = new URL(consent.url ?? "").searchParams.get("code");
  expect(code).toBeTruthy();
  return { code: code ?? "", nonce, verifier };
}

async function exchangeCode(
  client: ClientFixture,
  code: string,
  verifier: string,
): Promise<{ payload: TokenPayload; response: Response }> {
  const response = await exports.default.fetch(
    new Request(`${BASE_URL}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: client.redirectUri,
        code_verifier: verifier,
        client_id: client.clientId,
        client_secret: client.clientSecret,
      }),
    }),
  );
  return {
    payload: (await response.json()) as TokenPayload,
    response,
  };
}

async function issueTokens(options: {
  enableEndSession: boolean;
  refresh?: boolean;
  user?: Awaited<ReturnType<typeof createAuthenticatedUser>>;
}): Promise<IssuedTokens & { nonce: string }> {
  const client = await storeClient(options);
  const user =
    options.user ??
    (await createAuthenticatedUser(`${crypto.randomUUID()}@example.com`));
  const { code, nonce, verifier } = await authorize(
    client,
    user,
    options.refresh ? OFFLINE_SCOPES : OPENID_SCOPES,
  );
  const token = await exchangeCode(client, code, verifier);
  expect(token.response.status).toBe(200);
  expect(token.payload.access_token).toMatch(/^pg72_at_/);
  expect(token.payload.id_token).toMatch(/^[^.]+\.[^.]+\.[^.]+$/);
  if (options.refresh) {
    expect(token.payload.refresh_token).toMatch(/^pg72_rt_/);
  }
  return {
    client,
    nonce,
    payload: token.payload,
    sessionId: user.sessionId,
    userId: user.userId,
  };
}

async function rotateRefreshToken(
  issued: IssuedTokens,
  refreshToken = issued.payload.refresh_token ?? "",
): Promise<{ payload: TokenPayload; response: Response }> {
  const response = await exports.default.fetch(
    new Request(`${BASE_URL}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: issued.client.clientId,
        client_secret: issued.client.clientSecret,
      }),
    }),
  );
  return {
    payload: (await response.json()) as TokenPayload,
    response,
  };
}

async function introspectRefreshToken(
  issued: IssuedTokens,
  refreshToken = issued.payload.refresh_token ?? "",
): Promise<Record<string, unknown>> {
  const response = await exports.default.fetch(
    new Request(`${BASE_URL}/oauth2/introspect`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: issued.client.clientId,
        client_secret: issued.client.clientSecret,
        token: refreshToken,
        token_type_hint: "refresh_token",
      }),
    }),
  );
  expect(response.status).toBe(200);
  return (await response.json()) as Record<string, unknown>;
}

function decodeIdToken(token: string): Record<string, unknown> {
  const encoded = token.split(".")[1];
  if (!encoded) throw new Error("ID token payload is missing");
  const base64 = encoded
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(encoded.length / 4) * 4, "=");
  const bytes = Uint8Array.from(atob(base64), (character) =>
    character.charCodeAt(0),
  );
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
}

function tamperIdTokenSignature(token: string): string {
  const parts = token.split(".");
  const signature = parts[2];
  if (parts.length !== 3 || !signature) {
    throw new Error("ID token signature is missing");
  }
  const first = signature[0] === "A" ? "B" : "A";
  return [parts[0], parts[1], `${first}${signature.slice(1)}`].join(".");
}

async function tokenCounts(clientId: string): Promise<TokenCounts> {
  const counts = await env.PG72_ID_DB.prepare(
    `SELECT
      (SELECT COUNT(*) FROM oauthAccessToken WHERE clientId = ?) AS access_tokens,
      (SELECT COUNT(*) FROM oauthRefreshToken WHERE clientId = ?) AS refresh_tokens`,
  )
    .bind(clientId, clientId)
    .first<TokenCounts>();
  if (!counts) throw new Error("Token counts were not returned");
  return counts;
}

async function expectRefreshRejectedWithoutWrites(
  issued: IssuedTokens,
): Promise<void> {
  const before = await tokenCounts(issued.client.clientId);
  const result = await rotateRefreshToken(issued);
  expect(result.response.status).toBe(400);
  expect(result.payload).toMatchObject({ error: "invalid_grant" });
  expect(result.payload).not.toHaveProperty("access_token");
  expect(result.payload).not.toHaveProperty("id_token");
  expect(result.payload).not.toHaveProperty("refresh_token");
  expect(await tokenCounts(issued.client.clientId)).toEqual(before);
}

describe("central sid contract", () => {
  it("emits one verified central sid for clients with end-session enabled or disabled", async () => {
    const user = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const disabled = await issueTokens({
      enableEndSession: false,
      user,
    });
    const enabled = await issueTokens({ enableEndSession: true, user });
    const disabledClaims = decodeIdToken(disabled.payload.id_token ?? "");
    const enabledClaims = decodeIdToken(enabled.payload.id_token ?? "");

    expect(disabledClaims).toMatchObject({
      aud: disabled.client.clientId,
      iss: BASE_URL,
      nonce: disabled.nonce,
      sid: user.sessionId,
      sub: user.userId,
    });
    expect(enabledClaims).toMatchObject({
      aud: enabled.client.clientId,
      iss: BASE_URL,
      nonce: enabled.nonce,
      sid: user.sessionId,
      sub: user.userId,
    });
    expect(disabledClaims.sid).toBe(enabledClaims.sid);
    const visits = await env.PG72_ID_DB.prepare(
      `SELECT client_id
         FROM rp_session_client
        WHERE session_id = ?
        ORDER BY client_id`,
    )
      .bind(user.sessionId)
      .all<{ client_id: string }>();
    expect(visits.results.map((row) => row.client_id)).toEqual(
      [disabled.client.clientId, enabled.client.clientId].sort(),
    );

    // This endpoint verifies the signature, issuer, and client audience before
    // it trusts the signed sid and performs the session deletion.
    routeJwksFetchThroughWorker();
    const verificationQuery = new URLSearchParams({
      client_id: enabled.client.clientId,
      id_token_hint: enabled.payload.id_token ?? "",
      post_logout_redirect_uri: enabled.client.postLogoutRedirectUri,
    });
    const verification = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/end-session?${verificationQuery}`, {
        redirect: "manual",
      }),
    );
    expect(verification.status).toBe(302);
    expect(verification.headers.get("location")).toBe(
      enabled.client.postLogoutRedirectUri,
    );
  });

  it("keeps end-session disabled without withholding sid", async () => {
    const issued = await issueTokens({ enableEndSession: false });
    const claims = decodeIdToken(issued.payload.id_token ?? "");
    expect(claims.sid).toBe(issued.sessionId);

    const query = new URLSearchParams({
      client_id: issued.client.clientId,
      id_token_hint: issued.payload.id_token ?? "",
    });
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/end-session?${query}`, {
        redirect: "manual",
      }),
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: "invalid_client" });
    const session = await env.PG72_ID_DB.prepare(
      "SELECT id FROM session WHERE id = ?",
    )
      .bind(issued.sessionId)
      .first<{ id: string }>();
    expect(session?.id).toBe(issued.sessionId);
  });

  it("rejects a tampered ID-token signature without deleting its session", async () => {
    const issued = await issueTokens({ enableEndSession: true });
    const tampered = tamperIdTokenSignature(issued.payload.id_token ?? "");
    expect(decodeIdToken(tampered)).toMatchObject({
      aud: issued.client.clientId,
      sid: issued.sessionId,
    });

    const outboxBefore = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM logout_delivery WHERE session_id = ?",
    )
      .bind(issued.sessionId)
      .first<{ count: number }>();
    routeJwksFetchThroughWorker();
    const query = new URLSearchParams({
      client_id: issued.client.clientId,
      id_token_hint: tampered,
    });
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/end-session?${query}`, {
        redirect: "manual",
      }),
    );
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.headers.get("location")).toBeNull();
    const session = await env.PG72_ID_DB.prepare(
      "SELECT id FROM session WHERE id = ?",
    )
      .bind(issued.sessionId)
      .first<{ id: string }>();
    expect(session?.id).toBe(issued.sessionId);
    const outboxAfter = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM logout_delivery WHERE session_id = ?",
    )
      .bind(issued.sessionId)
      .first<{ count: number }>();
    expect(outboxAfter?.count).toBe(outboxBefore?.count);
  });

  it("deletes the central session through enabled end-session and blocks refresh", async () => {
    const issued = await issueTokens({ enableEndSession: true, refresh: true });
    const claims = decodeIdToken(issued.payload.id_token ?? "");
    expect(claims.sid).toBe(issued.sessionId);

    routeJwksFetchThroughWorker();
    const query = new URLSearchParams({
      client_id: issued.client.clientId,
      id_token_hint: issued.payload.id_token ?? "",
      post_logout_redirect_uri: issued.client.postLogoutRedirectUri,
      state: "logout-state",
    });
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/end-session?${query}`, {
        redirect: "manual",
      }),
    );
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      `${issued.client.postLogoutRedirectUri}?state=logout-state`,
    );
    const session = await env.PG72_ID_DB.prepare(
      "SELECT id FROM session WHERE id = ?",
    )
      .bind(issued.sessionId)
      .first<{ id: string }>();
    expect(session).toBeNull();
    const detached = await env.PG72_ID_DB.prepare(
      "SELECT sessionId, revoked FROM oauthRefreshToken WHERE clientId = ?",
    )
      .bind(issued.client.clientId)
      .first<{ revoked: string | null; sessionId: string | null }>();
    expect(detached?.sessionId).toBeNull();
    expect(detached?.revoked).not.toBeNull();
    const outbox = await env.PG72_ID_DB.prepare(
      `SELECT client_id, last_error_code, reason, status
         FROM logout_delivery
        WHERE session_id = ? AND client_id = ?
        LIMIT 1`,
    )
      .bind(issued.sessionId, issued.client.clientId)
      .first<{
        client_id: string;
        last_error_code: string | null;
        reason: string;
        status: string;
      }>();
    expect(outbox).toEqual({
      client_id: issued.client.clientId,
      last_error_code: "missing_backchannel_uri",
      reason: "rp_initiated_logout",
      status: "dead",
    });

    const rejected = await rotateRefreshToken(issued);
    expect(rejected.response.status).toBe(400);
    expect(rejected.payload).toMatchObject({ error: "invalid_grant" });
    expect(rejected.payload).not.toHaveProperty("access_token");
    // Global logout marks the refresh row revoked in the source transaction.
    // Presenting that revoked token then triggers the provider's existing
    // refresh-family teardown, so no stale family row remains.
    expect(await tokenCounts(issued.client.clientId)).toEqual({
      access_tokens: 0,
      refresh_tokens: 0,
    });
    expect(await introspectRefreshToken(issued)).toEqual({ active: false });
  });

  it("preserves sid and auth_time across live refresh rotation", async () => {
    const issued = await issueTokens({ enableEndSession: false, refresh: true });
    const initialClaims = decodeIdToken(issued.payload.id_token ?? "");
    const rotation = await rotateRefreshToken(issued);
    expect(rotation.response.status).toBe(200);
    expect(rotation.payload.id_token).toMatch(/^[^.]+\.[^.]+\.[^.]+$/);
    expect(rotation.payload.refresh_token).toMatch(/^pg72_rt_/);
    const rotatedClaims = decodeIdToken(rotation.payload.id_token ?? "");

    expect(initialClaims.sid).toBe(issued.sessionId);
    expect(rotatedClaims.sid).toBe(issued.sessionId);
    expect(rotatedClaims.auth_time).toBe(initialClaims.auth_time);
    expect(await introspectRefreshToken(issued, rotation.payload.refresh_token)).toMatchObject({
      active: true,
      sid: issued.sessionId,
      sub: issued.userId,
    });

    const accessRows = await env.PG72_ID_DB.prepare(
      "SELECT sessionId FROM oauthAccessToken WHERE clientId = ?",
    )
      .bind(issued.client.clientId)
      .all<{ sessionId: string | null }>();
    const refreshRows = await env.PG72_ID_DB.prepare(
      "SELECT sessionId FROM oauthRefreshToken WHERE clientId = ?",
    )
      .bind(issued.client.clientId)
      .all<{ sessionId: string | null }>();
    expect(accessRows.results).not.toHaveLength(0);
    expect(refreshRows.results).not.toHaveLength(0);
    expect(accessRows.results.every((row) => row.sessionId === issued.sessionId)).toBe(
      true,
    );
    expect(
      refreshRows.results.every((row) => row.sessionId === issued.sessionId),
    ).toBe(true);
  });

  it("rejects a detached refresh token without creating partial tokens", async () => {
    const issued = await issueTokens({ enableEndSession: false, refresh: true });
    await env.PG72_ID_DB.prepare("DELETE FROM session WHERE id = ?")
      .bind(issued.sessionId)
      .run();

    await expectRefreshRejectedWithoutWrites(issued);
    expect(await introspectRefreshToken(issued)).toEqual({ active: false });
  });

  it("rejects an expired refresh-token session without creating partial tokens", async () => {
    const issued = await issueTokens({ enableEndSession: false, refresh: true });
    await env.PG72_ID_DB.prepare(
      "UPDATE session SET expiresAt = ? WHERE id = ?",
    )
      .bind(new Date(0).toISOString(), issued.sessionId)
      .run();

    await expectRefreshRejectedWithoutWrites(issued);
    expect(await introspectRefreshToken(issued)).toEqual({ active: false });
  });

  it("rejects a refresh token bound to another user's session", async () => {
    const issued = await issueTokens({ enableEndSession: false, refresh: true });
    const otherUser = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await env.PG72_ID_DB.prepare(
      "UPDATE oauthRefreshToken SET sessionId = ? WHERE clientId = ?",
    )
      .bind(otherUser.sessionId, issued.client.clientId)
      .run();

    await expectRefreshRejectedWithoutWrites(issued);
    expect(await introspectRefreshToken(issued)).toEqual({ active: false });
  });

  it("rejects an authorization code whose session belongs to another user", async () => {
    const client = await storeClient({ enableEndSession: false });
    const user = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const otherUser = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const { code, verifier } = await authorize(client, user, OPENID_SCOPES);
    await env.PG72_ID_DB.prepare("UPDATE session SET userId = ? WHERE id = ?")
      .bind(otherUser.userId, user.sessionId)
      .run();

    const token = await exchangeCode(client, code, verifier);
    expect(token.response.status).toBe(400);
    expect(token.payload).toMatchObject({ error: "invalid_request" });
    expect(token.payload).not.toHaveProperty("access_token");
    expect(token.payload).not.toHaveProperty("id_token");
    expect(await tokenCounts(client.clientId)).toEqual({
      access_tokens: 0,
      refresh_tokens: 0,
    });
  });

  it("keeps client credentials independent of user sessions and ID tokens", async () => {
    const client = await storeClient({ enableEndSession: false });
    await env.PG72_ID_DB.prepare(
      `UPDATE oauthClient
          SET grantTypes = '["client_credentials"]', scopes = '["service.read"]'
        WHERE clientId = ?`,
    )
      .bind(client.clientId)
      .run();

    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: client.clientId,
          client_secret: client.clientSecret,
          grant_type: "client_credentials",
          scope: "service.read",
        }),
      }),
    );
    expect(response.status).toBe(200);
    const payload = (await response.json()) as TokenPayload;
    expect(payload.access_token).toMatch(/^pg72_at_/);
    expect(payload).not.toHaveProperty("id_token");
    expect(payload).not.toHaveProperty("refresh_token");

    const accessToken = await env.PG72_ID_DB.prepare(
      "SELECT sessionId, userId FROM oauthAccessToken WHERE clientId = ?",
    )
      .bind(client.clientId)
      .first<{ sessionId: string | null; userId: string | null }>();
    expect(accessToken).toEqual({ sessionId: null, userId: null });
  });

  it("continues advertising sid as a supported claim", async () => {
    const response = await exports.default.fetch(
      `${BASE_URL}/.well-known/openid-configuration`,
    );
    expect(response.status).toBe(200);
    const metadata = (await response.json()) as {
      backchannel_logout_session_supported?: boolean;
      backchannel_logout_supported?: boolean;
      claims_supported?: string[];
    };
    expect(metadata.backchannel_logout_supported).toBe(true);
    expect(metadata.backchannel_logout_session_supported).toBe(true);
    expect(metadata.claims_supported).toEqual(
      expect.arrayContaining([
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "nonce",
        "sid",
        "acr",
        "scope",
        "azp",
        "email",
        "email_verified",
        "name",
        "picture",
        "family_name",
        "given_name",
        "https://pg72.tw/role",
      ]),
    );
  });
});
