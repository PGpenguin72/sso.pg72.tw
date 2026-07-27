import { env, exports } from "cloudflare:workers";
import {
  createExecutionContext,
  waitOnExecutionContext,
} from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { app, introspectionRateLimitKeys } from "../worker/index";
import { createAuth } from "../worker/auth";
import {
  CLIENT_SECRET_PREFIX,
  MAIL_INTROSPECTION_CLIENT_ID,
  WEBMAIL_CLIENT_ID,
} from "../worker/config";
import {
  continueCurrentAccountSelection,
  createAuthenticatedUser,
  sha256Base64Url,
} from "./helpers";

const BASE_URL = "http://localhost:5173";
const PROVISION_URL =
  `${BASE_URL}/api/admin/clients/provision-mail-introspector`;
const INTROSPECTION_ONLY_GRANT = "urn:pg72:grant-type:introspection-only";

interface ClientCredentials {
  clientId: string;
  clientSecret: string;
}

interface IssuedTokens extends ClientCredentials {
  accessToken: string;
  email: string;
  idToken: string;
  refreshToken?: string;
  sessionId: string;
  userId: string;
}

interface IntrospectionPayload {
  active?: boolean;
  client_id?: string;
  email?: string;
  email_verified?: boolean;
  error?: string;
  exp?: number;
  iat?: number;
  iss?: string;
  scope?: string;
  sid?: string;
  sub?: string;
  token_type?: string;
}

interface IntrospectionResult {
  payload: IntrospectionPayload;
  response: Response;
}

function base64UrlJson(value: Record<string, unknown>): string {
  return btoa(JSON.stringify(value))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function decodeBase64UrlJson<T>(value: string): T {
  const base64 = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return JSON.parse(atob(base64)) as T;
}

beforeEach(async () => {
  await env.PG72_ID_DB.prepare(
    "DELETE FROM oauthClient WHERE clientId IN (?, ?)",
  )
    .bind(MAIL_INTROSPECTION_CLIENT_ID, WEBMAIL_CLIENT_ID)
    .run();
});

async function storeClient(options: {
  clientId: string;
  clientSecret: string;
  grantTypes?: string[];
  scopes: string[];
  subjectType?: "pairwise" | "public";
}): Promise<void> {
  const now = new Date().toISOString();
  const redirectUri = `https://${options.clientId}.example/callback`;
  const secretSuffix = options.clientSecret.slice(CLIENT_SECRET_PREFIX.length);

  await env.PG72_ID_DB.prepare(
    "DELETE FROM oauthClient WHERE clientId = ?",
  )
    .bind(options.clientId)
    .run();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO oauthClient (
      id, clientId, clientSecret, disabled, skipConsent, enableEndSession,
      subjectType, scopes, createdAt, updatedAt, name, redirectUris,
      postLogoutRedirectUris, tokenEndpointAuthMethod, grantTypes,
      responseTypes, public, type, requirePKCE
    ) VALUES (?, ?, ?, 0, 0, 1, ?, ?, ?, ?, ?, ?, ?,
              'client_secret_post', ?, '["code"]', 0, 'web', 1)`,
  )
    .bind(
      crypto.randomUUID(),
      options.clientId,
      await sha256Base64Url(secretSuffix),
      options.subjectType ?? "public",
      JSON.stringify(options.scopes),
      now,
      now,
      "Introspection Test Client",
      JSON.stringify([redirectUri]),
      JSON.stringify([`https://${options.clientId}.example/logout`]),
      JSON.stringify(options.grantTypes ?? ["authorization_code"]),
    )
    .run();
}

async function installMailIntrospector(
  options: { disabled?: boolean } = {},
): Promise<ClientCredentials> {
  const clientSecret = `${CLIENT_SECRET_PREFIX}${crypto.randomUUID()}`;
  const secretSuffix = clientSecret.slice(CLIENT_SECRET_PREFIX.length);
  const now = new Date().toISOString();

  await env.PG72_ID_DB.prepare(
    "DELETE FROM oauthClient WHERE clientId = ?",
  )
    .bind(MAIL_INTROSPECTION_CLIENT_ID)
    .run();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO oauthClient (
      id, clientId, clientSecret, disabled, skipConsent, enableEndSession,
      subjectType, scopes, createdAt, updatedAt, name, redirectUris,
      tokenEndpointAuthMethod, grantTypes, responseTypes, public, type,
      requirePKCE, ownerUserId, metadata
    ) VALUES (?, ?, ?, ?, 0, 0, 'public', '[]', ?, ?, ?, '[]',
              'client_secret_post', ?, '[]', 0, 'service', 1, NULL, ?)`,
  )
    .bind(
      crypto.randomUUID(),
      MAIL_INTROSPECTION_CLIENT_ID,
      await sha256Base64Url(secretSuffix),
      options.disabled ? 1 : 0,
      now,
      now,
      "PGID Mail Token Introspection",
      JSON.stringify([INTROSPECTION_ONLY_GRANT]),
      JSON.stringify({
        introspectionTargetClientId: WEBMAIL_CLIENT_ID,
        purpose: "mail-token-introspection",
      }),
    )
    .run();

  return { clientId: MAIL_INTROSPECTION_CLIENT_ID, clientSecret };
}

async function issueTokens(
  scopes: string[],
  options: {
    clientId?: string;
    emailVerified?: boolean;
    refresh?: boolean;
    subjectType?: "pairwise" | "public";
  } = {},
): Promise<IssuedTokens> {
  const clientId = options.clientId ?? WEBMAIL_CLIENT_ID;
  const clientSecret = `${CLIENT_SECRET_PREFIX}${crypto.randomUUID()}`;
  const redirectUri = `https://${clientId}.example/callback`;
  const verifier = "introspection-verifier-introspection-verifier";
  const challenge = await sha256Base64Url(verifier);
  const email = `${crypto.randomUUID()}@example.com`;
  const user = await createAuthenticatedUser(email);

  if (options.emailVerified === false) {
    await env.PG72_ID_DB.prepare(
      "UPDATE user SET emailVerified = 0 WHERE id = ?",
    )
      .bind(user.userId)
      .run();
  }

  await storeClient({
    clientId,
    clientSecret,
    grantTypes: options.refresh
      ? ["authorization_code", "refresh_token"]
      : ["authorization_code"],
    scopes,
    subjectType: options.subjectType,
  });

  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: scopes.join(" "),
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "S".repeat(43),
    nonce: "N".repeat(43),
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

  const tokenResponse = await exports.default.fetch(
    new Request(`${BASE_URL}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code ?? "",
        redirect_uri: redirectUri,
        code_verifier: verifier,
        client_id: clientId,
        client_secret: clientSecret,
      }),
    }),
  );
  expect(tokenResponse.status).toBe(200);
  const token = (await tokenResponse.json()) as {
    access_token?: string;
    id_token?: string;
    refresh_token?: string;
  };
  expect(token.access_token).toMatch(/^pg72_at_/);
  expect(token.id_token).toMatch(/^[^.]+\.[^.]+\.[^.]+$/);
  if (options.refresh) expect(token.refresh_token).toMatch(/^pg72_rt_/);

  return {
    accessToken: token.access_token ?? "",
    clientId,
    clientSecret,
    email,
    idToken: token.id_token ?? "",
    refreshToken: token.refresh_token,
    sessionId: user.sessionId,
    userId: user.userId,
  };
}

async function introspect(
  caller: ClientCredentials,
  token: string,
  tokenTypeHint?: "access_token" | "refresh_token",
): Promise<IntrospectionResult> {
  const body = new URLSearchParams({
    client_id: caller.clientId,
    client_secret: caller.clientSecret,
    token,
  });
  if (tokenTypeHint) body.set("token_type_hint", tokenTypeHint);
  const response = await exports.default.fetch(
    new Request(`${BASE_URL}/oauth2/introspect`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    }),
  );
  return {
    payload: (await response.json()) as IntrospectionPayload,
    response,
  };
}

function expectInactive(result: IntrospectionResult): void {
  expect(result.response.status).toBe(200);
  expect(result.payload).toEqual({ active: false });
}

async function revoke(issued: IssuedTokens): Promise<Response> {
  return exports.default.fetch(
    new Request(`${BASE_URL}/oauth2/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: issued.clientId,
        client_secret: issued.clientSecret,
        token: issued.accessToken,
        token_type_hint: "access_token",
      }),
    }),
  );
}

describe("Mail access-token introspection", () => {
  it("returns only the verified mailbox identity for a live webmail token", async () => {
    const mail = await installMailIntrospector();
    const issued = await issueTokens(["openid", "profile", "email"]);

    const result = await introspect(mail, issued.accessToken);

    expect(result.response.status).toBe(200);
    expect(result.response.headers.get("cache-control")).toBe("no-store");
    expect(result.response.headers.get("pragma")).toBe("no-cache");
    expect(result.payload).toEqual({
      active: true,
      client_id: WEBMAIL_CLIENT_ID,
      email: issued.email,
      email_verified: true,
      exp: expect.any(Number),
      iat: expect.any(Number),
      iss: BASE_URL,
      scope: "openid profile email",
    });
  });

  it("rejects unverified, unscoped, unrelated, and suspended identities", async () => {
    const mail = await installMailIntrospector();

    const unverified = await issueTokens(["openid", "email"], {
      emailVerified: false,
    });
    expectInactive(await introspect(mail, unverified.accessToken));

    const unscoped = await issueTokens(["openid", "profile"]);
    expectInactive(await introspect(mail, unscoped.accessToken));

    const unrelated = await issueTokens(["openid", "email"], {
      clientId: `unrelated-${crypto.randomUUID()}`,
    });
    expectInactive(await introspect(mail, unrelated.accessToken));

    const suspended = await issueTokens(["openid", "email"]);
    await env.PG72_ID_DB.prepare(
      "UPDATE user SET status = 'suspended' WHERE id = ?",
    )
      .bind(suspended.userId)
      .run();
    expectInactive(await introspect(mail, suspended.accessToken));
  });

  it("requires the access token to retain a live central session", async () => {
    const mail = await installMailIntrospector();
    const issued = await issueTokens(["openid", "email"]);
    expect((await introspect(mail, issued.accessToken)).payload.active).toBe(true);

    await env.PG72_ID_DB.prepare(
      "UPDATE session SET expiresAt = ? WHERE id = ?",
    )
      .bind(new Date(0).toISOString(), issued.sessionId)
      .run();

    const row = await env.PG72_ID_DB.prepare(
      "SELECT sessionId FROM oauthAccessToken WHERE userId = ?",
    )
      .bind(issued.userId)
      .first<{ sessionId: string | null }>();
    expect(row?.sessionId).toBe(issued.sessionId);

    expectInactive(await introspect(mail, issued.accessToken));

    await env.PG72_ID_DB.prepare("DELETE FROM session WHERE id = ?")
      .bind(issued.sessionId)
      .run();
    const detached = await env.PG72_ID_DB.prepare(
      "SELECT sessionId FROM oauthAccessToken WHERE userId = ?",
    )
      .bind(issued.userId)
      .first<{ sessionId: string | null }>();
    expect(detached?.sessionId).toBeNull();
    expectInactive(await introspect(mail, issued.accessToken));
  });

  it("normalizes unknown, expired, revoked, and disabled-target tokens", async () => {
    const mail = await installMailIntrospector();
    const issued = await issueTokens(["openid", "email"]);

    expectInactive(await introspect(mail, "pg72_at_unknown"));

    const jwksResponse = await exports.default.fetch(
      `${BASE_URL}/.well-known/jwks.json`,
    );
    const jwks = (await jwksResponse.json()) as {
      keys: Array<{ kid?: string }>;
    };
    const issuedHeader = decodeBase64UrlJson<{ kid?: string }>(
      issued.idToken.split(".")[0] ?? "",
    );
    expect(issuedHeader.kid).toEqual(expect.any(String));
    expect(jwks.keys.some((key) => key.kid === issuedHeader.kid)).toBe(true);
    const rotationKeyId = crypto.randomUUID();
    const insertedRotationKey = await env.PG72_ID_DB.prepare(
      `INSERT INTO jwks (id, publicKey, privateKey, createdAt, expiresAt)
       SELECT ?, publicKey, privateKey, createdAt, expiresAt
         FROM jwks
        ORDER BY createdAt DESC
        LIMIT 1`,
    )
      .bind(rotationKeyId)
      .run();
    expect(insertedRotationKey.meta.changes).toBe(1);
    try {
      const rotatingJwksResponse = await exports.default.fetch(
        `${BASE_URL}/.well-known/jwks.json`,
      );
      const rotatingJwks = (await rotatingJwksResponse.json()) as {
        keys: Array<{ kid?: string }>;
      };
      expect(rotatingJwks.keys.length).toBeGreaterThanOrEqual(2);
      const noKidJwt = [
        base64UrlJson({ alg: "EdDSA", typ: "JWT" }),
        base64UrlJson({
          aud: "https://api.pg72.tw",
          azp: WEBMAIL_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          iss: BASE_URL,
        }),
        "A".repeat(86),
      ].join(".");
      expectInactive(await introspect(mail, noKidJwt));
    } finally {
      await env.PG72_ID_DB.prepare("DELETE FROM jwks WHERE id = ?")
        .bind(rotationKeyId)
        .run();
    }

    const invalidJwt = [
      base64UrlJson({ alg: "EdDSA", kid: jwks.keys[0]?.kid, typ: "JWT" }),
      base64UrlJson({
        aud: "https://api.pg72.tw",
        azp: WEBMAIL_CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 60,
        iss: BASE_URL,
      }),
      "A".repeat(86),
    ].join(".");
    expectInactive(await introspect(mail, invalidJwt));

    const unknownKidJwt = [
      base64UrlJson({ alg: "EdDSA", kid: "unknown-kid", typ: "JWT" }),
      base64UrlJson({
        aud: "https://api.pg72.tw",
        azp: WEBMAIL_CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 60,
        iss: BASE_URL,
      }),
      "A".repeat(86),
    ].join(".");
    expectInactive(await introspect(mail, unknownKidJwt));

    const unsupportedAlgorithmJwt = [
      base64UrlJson({ alg: "HS256", kid: jwks.keys[0]?.kid, typ: "JWT" }),
      base64UrlJson({
        aud: "https://api.pg72.tw",
        azp: WEBMAIL_CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 60,
        iss: BASE_URL,
      }),
      "A".repeat(43),
    ].join(".");
    expectInactive(await introspect(mail, unsupportedAlgorithmJwt));
    expectInactive(await introspect(mail, issued.idToken));
    const signedWebmailJwt = await createAuth(env).api.signJWT({
      body: {
        payload: {
          azp: WEBMAIL_CLIENT_ID,
          scope: "openid email",
          sub: issued.userId,
        },
      },
    });
    expectInactive(await introspect(mail, signedWebmailJwt.token));

    const tokenHash = await sha256Base64Url(
      issued.accessToken.slice("pg72_at_".length),
    );
    await env.PG72_ID_DB.prepare(
      "UPDATE oauthAccessToken SET expiresAt = ? WHERE token = ?",
    )
      .bind(new Date(0).toISOString(), tokenHash)
      .run();
    expectInactive(await introspect(mail, issued.accessToken));

    await env.PG72_ID_DB.prepare(
      "UPDATE oauthAccessToken SET expiresAt = ? WHERE token = ?",
    )
      .bind(new Date(Date.now() + 60_000).toISOString(), tokenHash)
      .run();
    expect((await revoke(issued)).status).toBe(200);
    expectInactive(await introspect(mail, issued.accessToken));

    const disabledTarget = await issueTokens(["openid", "email"]);
    await env.PG72_ID_DB.prepare(
      "UPDATE oauthClient SET disabled = 1 WHERE clientId = ?",
    )
      .bind(WEBMAIL_CLIENT_ID)
      .run();
    expectInactive(await introspect(mail, disabledTarget.accessToken));
  });

  it("never delegates refresh tokens and treats token_type_hint as a hint", async () => {
    const mail = await installMailIntrospector();
    const issued = await issueTokens(
      ["openid", "profile", "email", "offline_access"],
      { refresh: true },
    );
    const owner = {
      clientId: issued.clientId,
      clientSecret: issued.clientSecret,
    };

    expectInactive(
      await introspect(mail, issued.refreshToken ?? "", "access_token"),
    );
    const ownerRefresh = await introspect(
      owner,
      issued.refreshToken ?? "",
      "access_token",
    );
    expect(ownerRefresh.response.status).toBe(200);
    expect(ownerRefresh.payload).toMatchObject({
      active: true,
      client_id: WEBMAIL_CLIENT_ID,
    });
    const ownerAccess = await introspect(
      owner,
      issued.accessToken,
      "refresh_token",
    );
    expect(ownerAccess.response.status).toBe(200);
    expect(ownerAccess.payload.active).toBe(true);
  });

  it("returns 401 for invalid or disabled introspection clients", async () => {
    const mail = await installMailIntrospector();
    const issued = await issueTokens(["openid", "email"]);

    const unknownClient = await introspect(
      {
        clientId: "unknown-introspection-client",
        clientSecret: `${CLIENT_SECRET_PREFIX}wrong`,
      },
      issued.accessToken,
    );
    expect(unknownClient.response.status).toBe(401);
    expect(unknownClient.payload).toEqual({ error: "invalid_client" });

    const wrongSecret = await introspect(
      { ...mail, clientSecret: `${CLIENT_SECRET_PREFIX}wrong` },
      issued.accessToken,
    );
    expect(wrongSecret.response.status).toBe(401);
    expect(wrongSecret.payload).toEqual({ error: "invalid_client" });

    await env.PG72_ID_DB.prepare(
      "UPDATE oauthClient SET disabled = 1 WHERE clientId = ?",
    )
      .bind(MAIL_INTROSPECTION_CLIENT_ID)
      .run();
    const disabled = await introspect(mail, issued.accessToken);
    expect(disabled.response.status).toBe(401);
    expect(disabled.payload).toEqual({ error: "invalid_client" });
  });
});

describe("Mail introspection service client", () => {
  it("provisions an unowned, non-token-issuing client for manage-all admins", async () => {
    const developer = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "developer",
    );
    const denied = await exports.default.fetch(
      new Request(PROVISION_URL, { method: "POST", headers: developer.headers }),
    );
    expect(denied.status).toBe(403);

    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
      { passkeyStepUp: true },
    );
    await env.PG72_ID_DB.prepare(
      "UPDATE session SET createdAt = ? WHERE id = ?",
    )
      .bind(new Date(0).toISOString(), admin.sessionId)
      .run();
    const stale = await exports.default.fetch(
      new Request(PROVISION_URL, { method: "POST", headers: admin.headers }),
    );
    expect(stale.status).toBe(403);
    expect(await stale.json()).toMatchObject({
      code: "SESSION_NOT_FRESH",
      error: "fresh_session_required",
    });
    await env.PG72_ID_DB.prepare(
      "UPDATE session SET createdAt = ? WHERE id = ?",
    )
      .bind(new Date(Date.now() + 60_000).toISOString(), admin.sessionId)
      .run();
    const futureDated = await exports.default.fetch(
      new Request(PROVISION_URL, { method: "POST", headers: admin.headers }),
    );
    expect(futureDated.status).toBe(403);
    expect(await futureDated.json()).toMatchObject({
      code: "SESSION_NOT_FRESH",
      error: "fresh_session_required",
    });
    await env.PG72_ID_DB.prepare(
      "UPDATE session SET createdAt = ? WHERE id = ?",
    )
      .bind(new Date().toISOString(), admin.sessionId)
      .run();
    const response = await exports.default.fetch(
      new Request(PROVISION_URL, { method: "POST", headers: admin.headers }),
    );
    expect(response.status).toBe(201);
    const payload = (await response.json()) as {
      client: {
        clientId: string;
        grantTypes: string[];
        ownerUserId: string | null;
        redirectUris: string[];
        scopes: string[];
        tokenEndpointAuthMethod: string;
      };
      clientSecret: string;
    };
    expect(payload.client).toMatchObject({
      clientId: MAIL_INTROSPECTION_CLIENT_ID,
      grantTypes: [INTROSPECTION_ONLY_GRANT],
      ownerUserId: null,
      redirectUris: [],
      scopes: [],
      tokenEndpointAuthMethod: "client_secret_post",
    });
    expect(payload.clientSecret).toMatch(/^pg72_cs_/);

    const row = await env.PG72_ID_DB.prepare(
      `SELECT clientSecret, grantTypes, ownerUserId, redirectUris, scopes, type
         FROM oauthClient WHERE clientId = ?`,
    )
      .bind(MAIL_INTROSPECTION_CLIENT_ID)
      .first<{
        clientSecret: string;
        grantTypes: string;
        ownerUserId: string | null;
        redirectUris: string;
        scopes: string;
        type: string;
      }>();
    const suffix = payload.clientSecret.slice(CLIENT_SECRET_PREFIX.length);
    expect(row).toMatchObject({
      clientSecret: await sha256Base64Url(suffix),
      grantTypes: JSON.stringify([INTROSPECTION_ONLY_GRANT]),
      ownerUserId: null,
      redirectUris: "[]",
      scopes: "[]",
      type: "service",
    });
    expect(row?.clientSecret).not.toContain(suffix);

    const tokenIssue = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: MAIL_INTROSPECTION_CLIENT_ID,
          client_secret: payload.clientSecret,
          grant_type: "client_credentials",
        }),
      }),
    );
    expect(tokenIssue.status).toBe(400);
    const tokenIssuePayload = (await tokenIssue.json()) as {
      access_token?: string;
      error?: string;
    };
    expect(tokenIssuePayload).toMatchObject({ error: "unauthorized_client" });
    expect(tokenIssuePayload).not.toHaveProperty("access_token");

    const authorizeQuery = new URLSearchParams({
      client_id: MAIL_INTROSPECTION_CLIENT_ID,
      redirect_uri: "https://mail-introspector.invalid/callback",
      response_type: "code",
      scope: "openid",
      code_challenge: "A".repeat(43),
      code_challenge_method: "S256",
      state: "S".repeat(43),
      nonce: "N".repeat(43),
    });
    const authorize = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/authorize?${authorizeQuery}`, {
        headers: admin.headers,
        redirect: "manual",
      }),
    );
    const authorizeEvidence = `${authorize.headers.get("location") ?? ""} ${await authorize.text()}`;
    expect(authorizeEvidence).toContain("error");
    expect(authorizeEvidence).not.toContain("code=");
    expect(authorizeEvidence).not.toContain("/consent");

    const audit = await env.PG72_ID_DB.prepare(
      `SELECT client_id, event_type, subject_id FROM audit_event
        WHERE event_type = 'oauth_client.created' AND client_id = ?`,
    )
      .bind(MAIL_INTROSPECTION_CLIENT_ID)
      .first<{
        client_id: string;
        event_type: string;
        subject_id: string;
      }>();
    expect(audit).toEqual({
      client_id: MAIL_INTROSPECTION_CLIENT_ID,
      event_type: "oauth_client.created",
      subject_id: admin.userId,
    });

    const duplicate = await exports.default.fetch(
      new Request(PROVISION_URL, { method: "POST", headers: admin.headers }),
    );
    expect(duplicate.status).toBe(409);
    expect(await duplicate.json()).toEqual({ error: "client_exists" });
  });

  it("reserves system IDs and requires manage-all for their lifecycle", async () => {
    const developer = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "developer",
      { passkeyStepUp: true },
    );
    const createTarget = await exports.default.fetch(
      new Request(`${BASE_URL}/api/admin/clients`, {
        method: "POST",
        headers: developer.headers,
        body: JSON.stringify({
          clientId: WEBMAIL_CLIENT_ID,
          name: "Webmail",
          developerName: "PG72 Mail",
          redirectUris: ["https://webmail.pg72.tw/callback"],
          scopes: ["openid", "email"],
          grantTypes: ["authorization_code"],
        }),
      }),
    );
    expect(createTarget.status).toBe(403);
    expect(await createTarget.json()).toEqual({ error: "reserved_client_id" });

    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
      { passkeyStepUp: true },
    );
    const provisioned = await exports.default.fetch(
      new Request(PROVISION_URL, { method: "POST", headers: admin.headers }),
    );
    const initial = (await provisioned.json()) as { clientSecret: string };
    expect(provisioned.status).toBe(201);

    const issued = await issueTokens(["openid", "email"]);
    expect(
      (
        await introspect(
          {
            clientId: MAIL_INTROSPECTION_CLIENT_ID,
            clientSecret: initial.clientSecret,
          },
          issued.accessToken,
        )
      ).payload.active,
    ).toBe(true);

    const beforeFailedRotation = await env.PG72_ID_DB.prepare(
      "SELECT clientSecret FROM oauthClient WHERE clientId = ?",
    )
      .bind(MAIL_INTROSPECTION_CLIENT_ID)
      .first<{ clientSecret: string }>();
    await env.PG72_ID_DB.prepare(
      `CREATE TRIGGER fail_client_audit
       BEFORE INSERT ON audit_event
       WHEN NEW.event_type = 'oauth_client.secret_rotated'
       BEGIN
         SELECT RAISE(ABORT, 'forced audit failure');
       END`,
    ).run();
    try {
      const failedRotation = await exports.default.fetch(
        new Request(
          `${BASE_URL}/api/admin/clients/${MAIL_INTROSPECTION_CLIENT_ID}/rotate-secret`,
          { method: "POST", headers: admin.headers },
        ),
      );
      expect(failedRotation.status).toBe(500);
      const afterFailedRotation = await env.PG72_ID_DB.prepare(
        "SELECT clientSecret FROM oauthClient WHERE clientId = ?",
      )
        .bind(MAIL_INTROSPECTION_CLIENT_ID)
        .first<{ clientSecret: string }>();
      expect(afterFailedRotation).toEqual(beforeFailedRotation);
    } finally {
      await env.PG72_ID_DB.prepare("DROP TRIGGER fail_client_audit").run();
    }

    const rotated = await exports.default.fetch(
      new Request(
        `${BASE_URL}/api/admin/clients/${MAIL_INTROSPECTION_CLIENT_ID}/rotate-secret`,
        { method: "POST", headers: admin.headers },
      ),
    );
    expect(rotated.status).toBe(200);
    const rotation = (await rotated.json()) as { clientSecret: string };
    expect(rotation.clientSecret).toMatch(/^pg72_cs_/);
    const oldSecret = await introspect(
      {
        clientId: MAIL_INTROSPECTION_CLIENT_ID,
        clientSecret: initial.clientSecret,
      },
      issued.accessToken,
    );
    expect(oldSecret.response.status).toBe(401);
    expect(
      (
        await introspect(
          {
            clientId: MAIL_INTROSPECTION_CLIENT_ID,
            clientSecret: rotation.clientSecret,
          },
          issued.accessToken,
        )
      ).payload.active,
    ).toBe(true);

    await env.PG72_ID_DB.prepare(
      "UPDATE user SET role = 'developer' WHERE id = ?",
    )
      .bind(admin.userId)
      .run();
    const demoted = await exports.default.fetch(
      new Request(
        `${BASE_URL}/api/admin/clients/${MAIL_INTROSPECTION_CLIENT_ID}/rotate-secret`,
        { method: "POST", headers: admin.headers },
      ),
    );
    expect(demoted.status).toBe(404);
  });

  it("returns one-time secrets when post-commit Queue fan-out fails", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
      { passkeyStepUp: true },
    );
    const auditBefore = await env.PG72_ID_DB.prepare(
      `SELECT
        SUM(CASE WHEN event_type = 'oauth_client.created' THEN 1 ELSE 0 END) AS created,
        SUM(CASE WHEN event_type = 'oauth_client.secret_rotated' THEN 1 ELSE 0 END) AS rotated
       FROM audit_event
       WHERE client_id = ?`,
    )
      .bind(MAIL_INTROSPECTION_CLIENT_ID)
      .first<{ created: number; rotated: number }>();
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const provisionEnv = {
        ...env,
        SECURITY_EVENTS: {
          send: () => {
            throw new Error("queue unavailable");
          },
        },
      } as unknown as Env;
      const provisionCtx = createExecutionContext();
      const provisioned = await app.fetch(
        new Request(PROVISION_URL, {
          method: "POST",
          headers: admin.headers,
        }),
        provisionEnv,
        provisionCtx,
      );
      await waitOnExecutionContext(provisionCtx);
      expect(provisioned.status).toBe(201);
      const initial = (await provisioned.json()) as { clientSecret: string };
      expect(initial.clientSecret).toMatch(/^pg72_cs_/);
      const initialHash = await env.PG72_ID_DB.prepare(
        "SELECT clientSecret FROM oauthClient WHERE clientId = ?",
      )
        .bind(MAIL_INTROSPECTION_CLIENT_ID)
        .first<{ clientSecret: string }>();
      expect(initialHash?.clientSecret).toBe(
        await sha256Base64Url(
          initial.clientSecret.slice(CLIENT_SECRET_PREFIX.length),
        ),
      );

      const rotationEnv = {
        ...env,
        SECURITY_EVENTS: {
          send: () => Promise.reject(new Error("queue rejected")),
        },
      } as unknown as Env;
      const rotationCtx = createExecutionContext();
      const rotated = await app.fetch(
        new Request(
          `${BASE_URL}/api/admin/clients/${MAIL_INTROSPECTION_CLIENT_ID}/rotate-secret`,
          { method: "POST", headers: admin.headers },
        ),
        rotationEnv,
        rotationCtx,
      );
      await waitOnExecutionContext(rotationCtx);
      expect(rotated.status).toBe(200);
      const rotation = (await rotated.json()) as { clientSecret: string };
      expect(rotation.clientSecret).toMatch(/^pg72_cs_/);
      const rotatedHash = await env.PG72_ID_DB.prepare(
        "SELECT clientSecret FROM oauthClient WHERE clientId = ?",
      )
        .bind(MAIL_INTROSPECTION_CLIENT_ID)
        .first<{ clientSecret: string }>();
      expect(rotatedHash?.clientSecret).toBe(
        await sha256Base64Url(
          rotation.clientSecret.slice(CLIENT_SECRET_PREFIX.length),
        ),
      );
      const auditAfter = await env.PG72_ID_DB.prepare(
        `SELECT
          SUM(CASE WHEN event_type = 'oauth_client.created' THEN 1 ELSE 0 END) AS created,
          SUM(CASE WHEN event_type = 'oauth_client.secret_rotated' THEN 1 ELSE 0 END) AS rotated
         FROM audit_event
         WHERE client_id = ?`,
      )
        .bind(MAIL_INTROSPECTION_CLIENT_ID)
        .first<{ created: number; rotated: number }>();
      expect(auditAfter).toEqual({
        created: (auditBefore?.created ?? 0) + 1,
        rotated: (auditBefore?.rotated ?? 0) + 1,
      });
      expect(log).toHaveBeenCalledTimes(2);
    } finally {
      log.mockRestore();
    }
  });

  it("does not commit a success audit when the client disappears mid-mutation", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
      { passkeyStepUp: true },
    );
    const provisioned = await exports.default.fetch(
      new Request(PROVISION_URL, { method: "POST", headers: admin.headers }),
    );
    expect(provisioned.status).toBe(201);

    const before = await env.PG72_ID_DB.prepare(
      `SELECT COUNT(*) AS count FROM audit_event
        WHERE event_type = 'oauth_client.secret_rotated' AND client_id = ?`,
    )
      .bind(MAIL_INTROSPECTION_CLIENT_ID)
      .first<{ count: number }>();

    await env.PG72_ID_DB.prepare(
      `CREATE TRIGGER delete_client_before_rotation
       BEFORE UPDATE OF clientSecret ON oauthClient
       WHEN OLD.clientId = 'pgid-mail-introspect'
       BEGIN
         DELETE FROM oauthClient WHERE clientId = OLD.clientId;
       END`,
    ).run();
    let rotation: Response;
    try {
      rotation = await exports.default.fetch(
        new Request(
          `${BASE_URL}/api/admin/clients/${MAIL_INTROSPECTION_CLIENT_ID}/rotate-secret`,
          { method: "POST", headers: admin.headers },
        ),
      );
    } finally {
      await env.PG72_ID_DB.prepare(
        "DROP TRIGGER delete_client_before_rotation",
      ).run();
    }
    expect(rotation.status).toBe(409);

    const after = await env.PG72_ID_DB.prepare(
      `SELECT COUNT(*) AS count FROM audit_event
        WHERE event_type = 'oauth_client.secret_rotated' AND client_id = ?`,
    )
      .bind(MAIL_INTROSPECTION_CLIENT_ID)
      .first<{ count: number }>();
    expect(after?.count).toBe(before?.count);
  });
});

describe("Introspection protocol boundary", () => {
  it("fails closed when a dedicated rate-limit binding is unavailable", async () => {
    let clientLimiterCalled = false;
    const testEnv = {
      ...env,
      INTROSPECTION_IP_RATE_LIMITER: {
        limit: async () => {
          throw new Error("rate-limit binding unavailable");
        },
      },
      INTROSPECTION_CLIENT_RATE_LIMITER: {
        limit: async () => {
          clientLimiterCalled = true;
          return { success: true };
        },
      },
    } as Env;
    const secret = `${CLIENT_SECRET_PREFIX}sensitive-secret`;
    const token = "pg72_at_sensitive-token";
    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${BASE_URL}/oauth2/introspect`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: MAIL_INTROSPECTION_CLIENT_ID,
          client_secret: secret,
          token,
        }),
      }),
      testEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(503);
    const text = await response.text();
    expect(JSON.parse(text)).toEqual({ error: "temporarily_unavailable" });
    expect(text).not.toContain(secret);
    expect(text).not.toContain(token);
    expect(clientLimiterCalled).toBe(false);
  });

  it("fails closed when the client-class rate limiter is unavailable", async () => {
    const testEnv = {
      ...env,
      INTROSPECTION_IP_RATE_LIMITER: {
        limit: async () => ({ success: true }),
      },
      INTROSPECTION_CLIENT_RATE_LIMITER: {
        limit: async () => {
          throw new Error("rate-limit binding unavailable");
        },
      },
    } as Env;
    const secret = `${CLIENT_SECRET_PREFIX}sensitive-secret`;
    const token = "pg72_at_sensitive-token";
    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${BASE_URL}/oauth2/introspect`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: MAIL_INTROSPECTION_CLIENT_ID,
          client_secret: secret,
          token,
        }),
      }),
      testEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(503);
    const text = await response.text();
    expect(JSON.parse(text)).toEqual({ error: "temporarily_unavailable" });
    expect(text).not.toContain(secret);
    expect(text).not.toContain(token);
  });

  it("uses dedicated non-secret rate-limit keys before provider work", async () => {
    const ip = "203.0.113.10";
    const keys: string[] = [];
    const testEnv = {
      ...env,
      AUTH_RATE_LIMITER: {
        limit: async () => {
          throw new Error("shared auth limiter must not run");
        },
      },
      INTROSPECTION_IP_RATE_LIMITER: {
        limit: async ({ key }: { key: string }) => {
          keys.push(key);
          return { success: true };
        },
      },
      INTROSPECTION_CLIENT_RATE_LIMITER: {
        limit: async ({ key }: { key: string }) => {
          keys.push(key);
          return { success: false };
        },
      },
    } as Env;
    const secret = `${CLIENT_SECRET_PREFIX}sensitive-secret`;
    const token = "pg72_at_sensitive-token";
    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${BASE_URL}/oauth2/introspect`, {
        method: "POST",
        headers: {
          "cf-connecting-ip": ip,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          client_id: MAIL_INTROSPECTION_CLIENT_ID,
          client_secret: secret,
          token,
        }),
      }),
      testEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(429);
    const text = await response.text();
    expect(JSON.parse(text)).toEqual({ error: "rate_limited" });
    expect(text).not.toContain(secret);
    expect(text).not.toContain(token);
    expect(keys).toEqual([
      introspectionRateLimitKeys(ip, null).ip,
      introspectionRateLimitKeys(ip, MAIL_INTROSPECTION_CLIENT_ID).clientIp,
    ]);
  });

  it("rejects Basic, duplicate fields, wrong methods/media, and large bodies", async () => {
    const mail = await installMailIntrospector();

    const get = await exports.default.fetch(`${BASE_URL}/oauth2/introspect`);
    expect(get.status).toBe(405);

    const wrongMedia = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/introspect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      }),
    );
    expect(wrongMedia.status).toBe(415);

    const prefixedMedia = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/introspect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded-invalid",
        },
        body: new URLSearchParams({
          client_id: mail.clientId,
          client_secret: mail.clientSecret,
          token: "pg72_at_unknown",
        }),
      }),
    );
    expect(prefixedMedia.status).toBe(415);

    const basic = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/introspect`, {
        method: "POST",
        headers: {
          Authorization: `Basic ${btoa(`${mail.clientId}:${mail.clientSecret}`)}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({ token: "pg72_at_unknown" }),
      }),
    );
    expect(basic.status).toBe(400);

    for (const duplicateName of [
      "client_id",
      "client_secret",
      "token",
      "token_type_hint",
    ]) {
      const body = new URLSearchParams({
        client_id: MAIL_INTROSPECTION_CLIENT_ID,
        client_secret: mail.clientSecret,
        token: "pg72_at_unknown",
        token_type_hint: "access_token",
      });
      body.append(duplicateName, body.get(duplicateName) ?? "duplicate");
      const duplicate = await exports.default.fetch(
        new Request(`${BASE_URL}/oauth2/introspect`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body,
        }),
      );
      expect(duplicate.status).toBe(400);
    }

    const oversized = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/introspect`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: mail.clientId,
          client_secret: mail.clientSecret,
          token: `pg72_at_${"x".repeat(5_000)}`,
        }),
      }),
    );
    expect(oversized.status).toBe(413);
  });
});
