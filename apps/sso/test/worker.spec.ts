import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import { readRuntimeConfig } from "../worker/config";
import { createAuthenticatedUser, sha256Base64Url } from "./helpers";

const COPY_REFRESH_MIGRATION = "0005_copy_refresh_grant.sql";

async function applyCopyRefreshGrantMigration(): Promise<void> {
  const migration = env.TEST_MIGRATIONS.find(
    ({ name }) => name === COPY_REFRESH_MIGRATION,
  );
  if (!migration) {
    throw new Error(`Missing test migration: ${COPY_REFRESH_MIGRATION}`);
  }

  await env.PG72_ID_DB.batch(
    migration.queries.map((query) => env.PG72_ID_DB.prepare(query)),
  );
}

async function createPasskey(userId: string, name: string): Promise<string> {
  const id = crypto.randomUUID();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO passkey
      (id, name, publicKey, userId, credentialID, counter, deviceType,
       backedUp, transports, createdAt, aaguid)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id,
      name,
      "test-public-key",
      userId,
      crypto.randomUUID(),
      0,
      "singleDevice",
      0,
      "internal",
      new Date().toISOString(),
      "00000000-0000-0000-0000-000000000000",
    )
    .run();
  return id;
}

describe("PGID Worker", () => {
  it("serves health with hardened browser headers", async () => {
    const response = await exports.default.fetch("http://sso.test/health");

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBeNull();
    expect(response.headers.get("content-security-policy")).toContain(
      "frame-ancestors 'none'",
    );
    expect(response.headers.get("content-security-policy")).toContain(
      "script-src 'self' 'nonce-cGc3Mi12aXRlLWRldg=='",
    );
    expect(response.headers.get("content-security-policy")).toContain(
      "style-src 'self' 'nonce-cGc3Mi12aXRlLWRldg=='",
    );
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("x-request-id")).toMatch(
      /^[0-9a-f]{8}-[0-9a-f-]{27}$/,
    );
  });

  it("publishes root issuer metadata with PKCE S256", async () => {
    const response = await exports.default.fetch(
      "http://localhost:5173/.well-known/openid-configuration",
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("max-age=300");
    const metadata = (await response.json()) as Record<string, unknown>;
    expect(metadata.issuer).toBe("http://localhost:5173");
    expect(metadata.authorization_endpoint).toBe(
      "http://localhost:5173/oauth2/authorize",
    );
    expect(metadata.token_endpoint).toBe("http://localhost:5173/oauth2/token");
    expect(metadata.code_challenge_methods_supported).toContain("S256");
    expect(metadata.token_endpoint_auth_methods_supported).toContain("none");
    expect(metadata.registration_endpoint).toBeUndefined();
  });

  it("does not expose unauthenticated dynamic registration", async () => {
    const response = await exports.default.fetch(
      new Request("http://localhost:5173/oauth2/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["https://attacker.example/cb"] }),
      }),
    );

    expect(response.status).toBeGreaterThanOrEqual(400);
  });

  it("returns an HTTP redirect for browser authorization navigation", async () => {
    await env.PG72_ID_DB.prepare(
      `INSERT INTO oauthClient (
        id, clientId, disabled, skipConsent, enableEndSession, subjectType,
        scopes, createdAt, updatedAt, name, redirectUris,
        postLogoutRedirectUris, tokenEndpointAuthMethod, grantTypes,
        responseTypes, public, type, requirePKCE
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        crypto.randomUUID(),
        "redirect-test-rp",
        0,
        0,
        1,
        "public",
        '["openid","profile","email"]',
        new Date().toISOString(),
        new Date().toISOString(),
        "Redirect Test RP",
        '["http://localhost:5174/callback"]',
        '["http://localhost:5174/"]',
        "none",
        '["authorization_code"]',
        '["code"]',
        1,
        "web",
        1,
      )
      .run();

    const query = new URLSearchParams({
      client_id: "redirect-test-rp",
      redirect_uri: "http://localhost:5174/callback",
      response_type: "code",
      scope: "openid profile email",
      code_challenge: "A".repeat(43),
      code_challenge_method: "S256",
      state: "B".repeat(43),
      nonce: "C".repeat(43),
    });
    const response = await exports.default.fetch(
      new Request(`http://localhost:5173/oauth2/authorize?${query}`, {
        headers: { "Sec-Fetch-Mode": "cors" },
        redirect: "manual",
      }),
    );

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") ?? "");
    expect(location.origin).toBe("http://localhost:5173");
    expect(location.pathname).toBe("/sign-in");
    expect(location.searchParams.get("client_id")).toBe("redirect-test-rp");
  });

  it("rejects OAuth clients that bypass user consent", async () => {
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthClient (
          id, clientId, skipConsent, redirectUris
        ) VALUES (?, ?, ?, ?)`,
      )
        .bind(
          crypto.randomUUID(),
          "consent-bypass-test-rp",
          1,
          '["https://client.example/callback"]',
        )
        .run(),
    ).rejects.toThrow("oauth consent cannot be skipped");
  });

  it("enables refresh grants only for existing confidential Copy clients", async () => {
    const now = new Date().toISOString();
    await env.PG72_ID_DB.prepare(
      "DELETE FROM oauthClient WHERE clientId IN ('pg72-copy-preview', 'pg72-copy')",
    ).run();
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthClient (
          id, clientId, clientSecret, disabled, skipConsent, scopes,
          createdAt, updatedAt, redirectUris, tokenEndpointAuthMethod,
          grantTypes, responseTypes, public, type, requirePKCE
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        "pg72-copy-preview",
        "hashed-preview-secret",
        0,
        0,
        '["openid","profile","email"]',
        now,
        now,
        '["https://sso-integration.cloud-clipboard-c1b.pages.dev/api/auth/callback/pg72-id"]',
        "client_secret_basic",
        '["authorization_code"]',
        '["code"]',
        0,
        "web",
        1,
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthClient (
          id, clientId, clientSecret, disabled, skipConsent, scopes,
          createdAt, updatedAt, redirectUris, tokenEndpointAuthMethod,
          grantTypes, responseTypes, public, type, requirePKCE
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        "pg72-copy",
        "hashed-production-secret",
        0,
        0,
        '["openid","profile","email"]',
        now,
        now,
        '["https://copy.pg72.tw/api/auth/callback/pg72-id"]',
        "client_secret_basic",
        '["authorization_code"]',
        '["code"]',
        0,
        "web",
        1,
      ),
    ]);

    await applyCopyRefreshGrantMigration();

    const clients = await env.PG72_ID_DB.prepare(
      `SELECT clientId, scopes, grantTypes, skipConsent, requirePKCE,
              public, tokenEndpointAuthMethod
         FROM oauthClient
        WHERE clientId IN ('pg72-copy-preview', 'pg72-copy')
        ORDER BY clientId`,
    ).all<{
      clientId: string;
      scopes: string;
      grantTypes: string;
      skipConsent: number;
      requirePKCE: number;
      public: number;
      tokenEndpointAuthMethod: string;
    }>();

    expect(clients.results).toHaveLength(2);
    for (const client of clients.results) {
      expect(JSON.parse(client.scopes)).toEqual([
        "openid",
        "profile",
        "email",
        "offline_access",
      ]);
      expect(JSON.parse(client.grantTypes)).toEqual([
        "authorization_code",
        "refresh_token",
      ]);
      expect(client).toMatchObject({
        skipConsent: 0,
        requirePKCE: 1,
        public: 0,
        tokenEndpointAuthMethod: "client_secret_basic",
      });
    }
  });

  it("does not create or upgrade an unsafe Copy client", async () => {
    const now = new Date().toISOString();
    await env.PG72_ID_DB.prepare(
      "DELETE FROM oauthClient WHERE clientId IN ('pg72-copy-preview', 'pg72-copy')",
    ).run();
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthClient (
          id, clientId, clientSecret, skipConsent, scopes, createdAt, updatedAt,
          redirectUris, tokenEndpointAuthMethod, grantTypes, public, requirePKCE
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        "pg72-copy-preview",
        null,
        0,
        '["openid","profile","email"]',
        now,
        now,
        '["https://attacker.example/callback"]',
        "none",
        '["authorization_code"]',
        1,
        0,
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthClient (
          id, clientId, clientSecret, skipConsent, scopes, createdAt, updatedAt,
          redirectUris, tokenEndpointAuthMethod, grantTypes, public, requirePKCE
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        "pg72-copy",
        "hashed-production-secret",
        0,
        '["openid","profile","email"]',
        now,
        now,
        "malformed-redirect-json",
        "client_secret_basic",
        '["authorization_code"]',
        0,
        1,
      ),
    ]);

    await applyCopyRefreshGrantMigration();

    const unsafeClients = await env.PG72_ID_DB.prepare(
      `SELECT clientId, scopes, grantTypes, tokenEndpointAuthMethod,
              public, requirePKCE
         FROM oauthClient
        WHERE clientId IN ('pg72-copy-preview', 'pg72-copy')
        ORDER BY clientId`,
    ).all<{
      clientId: string;
      scopes: string;
      grantTypes: string;
      tokenEndpointAuthMethod: string;
      public: number;
      requirePKCE: number;
    }>();
    const unknownClient = await env.PG72_ID_DB.prepare(
      "SELECT id FROM oauthClient WHERE clientId = 'pg72-copy-unknown'",
    ).first();

    expect(unsafeClients.results).toEqual([
      expect.objectContaining({
        clientId: "pg72-copy",
        scopes: '["openid","profile","email"]',
        grantTypes: '["authorization_code"]',
      }),
      expect.objectContaining({
        clientId: "pg72-copy-preview",
        scopes: '["openid","profile","email"]',
        grantTypes: '["authorization_code"]',
        tokenEndpointAuthMethod: "none",
        public: 1,
        requirePKCE: 0,
      }),
    ]);
    expect(unknownClient).toBeNull();
  });

  it("returns the relying-party callback after consent", async () => {
    const clientId = `consent-redirect-${crypto.randomUUID()}`;
    const callback = "https://client.example/callback";
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await env.PG72_ID_DB.prepare(
      `INSERT INTO oauthClient (
        id, clientId, disabled, skipConsent, scopes, name, redirectUris,
        tokenEndpointAuthMethod, grantTypes, responseTypes, public, requirePKCE
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        crypto.randomUUID(),
        clientId,
        0,
        0,
        '["openid","profile","email"]',
        "Consent Redirect Test",
        JSON.stringify([callback]),
        "none",
        '["authorization_code"]',
        '["code"]',
        1,
        1,
      )
      .run();

    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callback,
      response_type: "code",
      scope: "openid profile email",
      code_challenge: "A".repeat(43),
      code_challenge_method: "S256",
      state: "B".repeat(43),
      nonce: "C".repeat(43),
    });
    const authorizeResponse = await exports.default.fetch(
      new Request(`http://localhost:5173/oauth2/authorize?${query}`, {
        headers,
        redirect: "manual",
      }),
    );
    expect(authorizeResponse.status).toBe(302);
    const consentLocation = new URL(
      authorizeResponse.headers.get("location") ?? "",
      "http://localhost:5173",
    );
    expect(consentLocation.pathname).toBe("/consent");

    const consentHeaders = new Headers(headers);
    consentHeaders.set("Sec-Fetch-Mode", "cors");
    const consentResponse = await exports.default.fetch(
      new Request("http://localhost:5173/oauth2/consent", {
        method: "POST",
        headers: consentHeaders,
        body: JSON.stringify({
          accept: true,
          oauth_query: consentLocation.search.slice(1),
        }),
      }),
    );

    expect(consentResponse.status).toBe(200);
    const result = (await consentResponse.json()) as {
      redirect?: boolean;
      url?: string;
    };
    expect(result.redirect).toBe(true);
    const redirect = new URL(result.url ?? "");
    expect(redirect.origin + redirect.pathname).toBe(callback);
    expect(redirect.searchParams.has("code")).toBe(true);
    expect(redirect.searchParams.get("state")).toBe("B".repeat(43));
  });

  it("exchanges a confidential authorization code using the prefixed client secret", async () => {
    const clientId = `confidential-${crypto.randomUUID()}`;
    const clientSecretSuffix = crypto.randomUUID().replaceAll("-", "");
    const clientSecret = `pg72_cs_${clientSecretSuffix}`;
    const callback = "https://confidential.example/callback";
    const codeVerifier = "V".repeat(43);
    const codeChallenge = await sha256Base64Url(codeVerifier);
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    await env.PG72_ID_DB.prepare(
      `INSERT INTO oauthClient (
        id, clientId, clientSecret, disabled, skipConsent, scopes, name,
        redirectUris, tokenEndpointAuthMethod, grantTypes, responseTypes,
        public, requirePKCE
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        crypto.randomUUID(),
        clientId,
        await sha256Base64Url(clientSecretSuffix),
        0,
        0,
        '["openid","profile","email"]',
        "Confidential Exchange Test",
        JSON.stringify([callback]),
        "client_secret_basic",
        '["authorization_code"]',
        '["code"]',
        0,
        1,
      )
      .run();

    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callback,
      response_type: "code",
      scope: "openid profile email",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state: "D".repeat(43),
      nonce: "E".repeat(43),
    });
    const authorizeResponse = await exports.default.fetch(
      new Request(`http://localhost:5173/oauth2/authorize?${query}`, {
        headers,
        redirect: "manual",
      }),
    );
    const consentLocation = new URL(
      authorizeResponse.headers.get("location") ?? "",
      "http://localhost:5173",
    );
    expect(consentLocation.pathname).toBe("/consent");

    const consentHeaders = new Headers(headers);
    consentHeaders.set("Sec-Fetch-Mode", "cors");
    const consentResponse = await exports.default.fetch(
      new Request("http://localhost:5173/oauth2/consent", {
        method: "POST",
        headers: consentHeaders,
        body: JSON.stringify({
          accept: true,
          oauth_query: consentLocation.search.slice(1),
        }),
      }),
    );
    const consentResult = (await consentResponse.json()) as {
      redirect?: boolean;
      url?: string;
    };
    const authorizationCallback = new URL(consentResult.url ?? "");
    const code = authorizationCallback.searchParams.get("code");
    expect(code).toBeTruthy();

    const tokenResponse = await exports.default.fetch(
      new Request("http://localhost:5173/oauth2/token", {
        method: "POST",
        headers: {
          Accept: "application/json",
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code ?? "",
          redirect_uri: callback,
          code_verifier: codeVerifier,
        }),
      }),
    );

    expect(tokenResponse.status).toBe(200);
    expect(await tokenResponse.json()).toMatchObject({
      token_type: "Bearer",
      scope: "openid profile email",
    });
  });

  it("rotates offline refresh tokens and invalidates the family on reuse", async () => {
    const clientId = `refresh-rotation-${crypto.randomUUID()}`;
    const clientSecretSuffix = crypto.randomUUID().replaceAll("-", "");
    const clientSecret = `pg72_cs_${clientSecretSuffix}`;
    const callback = "https://refresh.example/callback";
    const codeVerifier = "R".repeat(43);
    const codeChallenge = await sha256Base64Url(codeVerifier);
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    await env.PG72_ID_DB.prepare(
      `INSERT INTO oauthClient (
        id, clientId, clientSecret, disabled, skipConsent, scopes, name,
        redirectUris, tokenEndpointAuthMethod, grantTypes, responseTypes,
        public, requirePKCE
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        crypto.randomUUID(),
        clientId,
        await sha256Base64Url(clientSecretSuffix),
        0,
        0,
        '["openid","profile","email","offline_access"]',
        "Refresh Rotation Test",
        JSON.stringify([callback]),
        "client_secret_basic",
        '["authorization_code","refresh_token"]',
        '["code"]',
        0,
        1,
      )
      .run();

    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callback,
      response_type: "code",
      scope: "openid profile email offline_access",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state: "F".repeat(43),
      nonce: "G".repeat(43),
    });
    const authorizeResponse = await exports.default.fetch(
      new Request(`http://localhost:5173/oauth2/authorize?${query}`, {
        headers,
        redirect: "manual",
      }),
    );
    expect(authorizeResponse.status).toBe(302);
    const consentLocation = new URL(
      authorizeResponse.headers.get("location") ?? "",
      "http://localhost:5173",
    );
    expect(consentLocation.pathname).toBe("/consent");

    const consentHeaders = new Headers(headers);
    consentHeaders.set("Sec-Fetch-Mode", "cors");
    const consentResponse = await exports.default.fetch(
      new Request("http://localhost:5173/oauth2/consent", {
        method: "POST",
        headers: consentHeaders,
        body: JSON.stringify({
          accept: true,
          oauth_query: consentLocation.search.slice(1),
        }),
      }),
    );
    expect(consentResponse.status).toBe(200);
    const consentResult = (await consentResponse.json()) as {
      redirect?: boolean;
      url?: string;
    };
    const code = new URL(consentResult.url ?? "").searchParams.get("code");
    expect(code).toBeTruthy();

    const tokenHeaders = {
      Accept: "application/json",
      Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
      "Content-Type": "application/x-www-form-urlencoded",
    };
    const initialResponse = await exports.default.fetch(
      new Request("http://localhost:5173/oauth2/token", {
        method: "POST",
        headers: tokenHeaders,
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code ?? "",
          redirect_uri: callback,
          code_verifier: codeVerifier,
        }),
      }),
    );
    expect(initialResponse.status).toBe(200);
    const initialTokens = (await initialResponse.json()) as {
      access_token?: string;
      refresh_token?: string;
      scope?: string;
      token_type?: string;
    };
    expect(initialTokens).toMatchObject({
      token_type: "Bearer",
      scope: "openid profile email offline_access",
    });
    expect(initialTokens.access_token).toMatch(/^pg72_at_/);
    expect(initialTokens.refresh_token).toMatch(/^pg72_rt_/);

    const rotate = (refreshToken: string) =>
      exports.default.fetch(
        new Request("http://localhost:5173/oauth2/token", {
          method: "POST",
          headers: tokenHeaders,
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: refreshToken,
          }),
        }),
      );

    const firstRotationResponse = await rotate(initialTokens.refresh_token ?? "");
    expect(firstRotationResponse.status).toBe(200);
    const firstRotation = (await firstRotationResponse.json()) as {
      access_token?: string;
      refresh_token?: string;
    };
    expect(firstRotation.access_token).toMatch(/^pg72_at_/);
    expect(firstRotation.refresh_token).toMatch(/^pg72_rt_/);
    expect(firstRotation.access_token).not.toBe(initialTokens.access_token);
    expect(firstRotation.refresh_token).not.toBe(initialTokens.refresh_token);

    const secondRotationResponse = await rotate(firstRotation.refresh_token ?? "");
    expect(secondRotationResponse.status).toBe(200);
    const secondRotation = (await secondRotationResponse.json()) as {
      access_token?: string;
      refresh_token?: string;
    };
    expect(secondRotation.access_token).toMatch(/^pg72_at_/);
    expect(secondRotation.refresh_token).toMatch(/^pg72_rt_/);
    expect(secondRotation.refresh_token).not.toBe(firstRotation.refresh_token);

    const reuseResponse = await rotate(initialTokens.refresh_token ?? "");
    expect(reuseResponse.status).toBe(400);
    expect(await reuseResponse.json()).toMatchObject({ error: "invalid_grant" });

    const family = await env.PG72_ID_DB.prepare(
      `SELECT
        (SELECT COUNT(*) FROM oauthRefreshToken
          WHERE clientId = ? AND userId = ?) AS refresh_tokens,
        (SELECT COUNT(*) FROM oauthAccessToken
          WHERE clientId = ? AND userId = ?) AS access_tokens`,
    )
      .bind(clientId, userId, clientId, userId)
      .first<{ refresh_tokens: number; access_tokens: number }>();
    expect(family).toEqual({ refresh_tokens: 0, access_tokens: 0 });

    const newestTokenResponse = await rotate(secondRotation.refresh_token ?? "");
    expect(newestTokenResponse.status).toBe(400);
    expect(await newestTokenResponse.json()).toMatchObject({
      error: "invalid_grant",
    });
  });

  it("revokes consent and every token issued to that application", async () => {
    const clientId = `revoke-test-${crypto.randomUUID()}`;
    const consentId = crypto.randomUUID();
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString();
    const legacyVerificationId = crypto.randomUUID();

    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthClient
          (id, clientId, skipConsent, scopes, name, uri, redirectUris)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        clientId,
        0,
        '["openid","email","offline_access"]',
        "Revocation Test",
        "https://client.example",
        '["https://client.example/callback"]',
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthConsent
          (id, clientId, userId, scopes, createdAt, updatedAt)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        consentId,
        clientId,
        userId,
        '["openid","email","offline_access"]',
        now.toISOString(),
        now.toISOString(),
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthRefreshToken
          (id, token, clientId, userId, expiresAt, createdAt, scopes)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        crypto.randomUUID(),
        clientId,
        userId,
        expiresAt,
        now.toISOString(),
        '["openid","email","offline_access"]',
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthAccessToken
          (id, token, clientId, userId, expiresAt, createdAt, scopes)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        crypto.randomUUID(),
        clientId,
        userId,
        expiresAt,
        now.toISOString(),
        '["openid","email","offline_access"]',
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO verification
          (id, identifier, value, expiresAt, createdAt, updatedAt)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        crypto.randomUUID(),
        JSON.stringify({
          type: "authorization_code",
          userId,
          query: { client_id: clientId },
        }),
        expiresAt,
        now.toISOString(),
        now.toISOString(),
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO verification
          (id, identifier, value, expiresAt, createdAt, updatedAt)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        legacyVerificationId,
        crypto.randomUUID(),
        "legacy-non-json-value",
        expiresAt,
        now.toISOString(),
        now.toISOString(),
      ),
    ]);

    const listResponse = await exports.default.fetch(
      new Request("http://localhost:5173/api/account/authorizations", {
        headers,
      }),
    );
    expect(listResponse.status).toBe(200);
    expect(await listResponse.json()).toMatchObject({
      authorizations: [{ id: consentId, clientId, name: "Revocation Test" }],
      canDeleteAccount: true,
    });

    const revokeResponse = await exports.default.fetch(
      new Request(
        `http://localhost:5173/api/account/authorizations/${consentId}`,
        { method: "DELETE", headers },
      ),
    );
    expect(revokeResponse.status).toBe(200);

    const remaining = await env.PG72_ID_DB.prepare(
      `SELECT
        (SELECT COUNT(*) FROM oauthConsent WHERE userId = ? AND clientId = ?) AS consents,
        (SELECT COUNT(*) FROM oauthAccessToken WHERE userId = ? AND clientId = ?) AS access_tokens,
        (SELECT COUNT(*) FROM oauthRefreshToken WHERE userId = ? AND clientId = ?) AS refresh_tokens,
        (SELECT COUNT(*) FROM verification
          WHERE CASE WHEN json_valid(value) THEN
            json_extract(value, '$.type') = 'authorization_code'
            AND json_extract(value, '$.userId') = ?
            AND json_extract(value, '$.query.client_id') = ?
          ELSE 0 END) AS authorization_codes`,
    )
      .bind(
        userId,
        clientId,
        userId,
        clientId,
        userId,
        clientId,
        userId,
        clientId,
      )
      .first<{
        authorization_codes: number;
        consents: number;
        access_tokens: number;
        refresh_tokens: number;
      }>();
    expect(remaining).toEqual({
      consents: 0,
      access_tokens: 0,
      refresh_tokens: 0,
      authorization_codes: 0,
    });
    const legacyVerification = await env.PG72_ID_DB.prepare(
      "SELECT id FROM verification WHERE id = ?",
    )
      .bind(legacyVerificationId)
      .first();
    expect(legacyVerification).not.toBeNull();
  });

  it("cannot revoke another user's authorization", async () => {
    const clientId = `cross-user-revoke-${crypto.randomUUID()}`;
    const consentId = crypto.randomUUID();
    const owner = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const attacker = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const now = new Date().toISOString();

    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthClient
          (id, clientId, skipConsent, scopes, name, redirectUris)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        clientId,
        0,
        '["openid","email"]',
        "Cross-user Revocation Test",
        '["https://client.example/callback"]',
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthConsent
          (id, clientId, userId, scopes, createdAt, updatedAt)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        consentId,
        clientId,
        owner.userId,
        '["openid","email"]',
        now,
        now,
      ),
    ]);

    const response = await exports.default.fetch(
      new Request(
        `http://localhost:5173/api/account/authorizations/${consentId}`,
        { method: "DELETE", headers: attacker.headers },
      ),
    );

    expect(response.status).toBe(404);
    const consent = await env.PG72_ID_DB.prepare(
      "SELECT id FROM oauthConsent WHERE id = ? AND userId = ?",
    )
      .bind(consentId, owner.userId)
      .first();
    expect(consent).not.toBeNull();
  });

  it("rejects cross-origin administrator invitation mutations", async () => {
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const invitedEmail = `${crypto.randomUUID()}@example.com`;
    headers.set("Origin", "https://attacker.example");

    const response = await exports.default.fetch(
      new Request("http://localhost:5173/api/admin/invitations", {
        method: "POST",
        headers,
        body: JSON.stringify({ email: invitedEmail, role: "user" }),
      }),
    );

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "invalid_origin" });
    const invitation = await env.PG72_ID_DB.prepare(
      "SELECT id FROM invitation WHERE email_normalized = ?",
    )
      .bind(invitedEmail)
      .first();
    expect(invitation).toBeNull();
  });

  it("rejects cross-origin administrator status mutations", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const target = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    admin.headers.set("Origin", "https://attacker.example");

    const response = await exports.default.fetch(
      new Request(
        `http://localhost:5173/api/admin/users/${target.userId}/status`,
        {
          method: "POST",
          headers: admin.headers,
          body: JSON.stringify({ suspended: true }),
        },
      ),
    );

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "invalid_origin" });
    const user = await env.PG72_ID_DB.prepare(
      "SELECT status FROM user WHERE id = ?",
    )
      .bind(target.userId)
      .first<{ status: string }>();
    expect(user?.status).toBe("active");
  });

  it("protects the bootstrap administrator from self-deletion", async () => {
    const email = env.BOOTSTRAP_ADMIN_EMAIL.trim().toLowerCase();
    const { headers, userId } = await createAuthenticatedUser(email, "admin");
    const response = await exports.default.fetch(
      new Request("http://localhost:5173/delete-user", {
        method: "POST",
        headers,
        body: "{}",
      }),
    );

    expect(response.status).toBe(403);
    const user = await env.PG72_ID_DB.prepare(
      "SELECT id FROM user WHERE id = ?",
    )
      .bind(userId)
      .first();
    expect(user).not.toBeNull();
  });

  it("allows a recently authenticated non-bootstrap admin to self-delete", async () => {
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const response = await exports.default.fetch(
      new Request("http://localhost:5173/delete-user", {
        method: "POST",
        headers,
        body: "{}",
      }),
    );

    expect(response.status).toBe(200);
    const user = await env.PG72_ID_DB.prepare(
      "SELECT id FROM user WHERE id = ?",
    )
      .bind(userId)
      .first();
    expect(user).toBeNull();
  });

  it("allows a recently authenticated regular user to self-delete", async () => {
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "user",
    );
    const response = await exports.default.fetch(
      new Request("http://localhost:5173/delete-user", {
        method: "POST",
        headers,
        body: "{}",
      }),
    );

    expect(response.status).toBe(200);
    const user = await env.PG72_ID_DB.prepare(
      "SELECT id FROM user WHERE id = ?",
    )
      .bind(userId)
      .first();
    expect(user).toBeNull();
  });

  it("blocks resource indicators while the stable provider lacks grant binding", async () => {
    const response = await exports.default.fetch(
      new Request("http://localhost:5173/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: "not-a-real-code",
          resource: "https://another-resource.example",
        }),
      }),
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_target" });
  });

  it("requires a session for account audit", async () => {
    const response = await exports.default.fetch(
      "http://localhost:5173/api/account/audit",
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "unauthorized" });
  });

  it("lists and renames only the authenticated user's passkeys", async () => {
    const owner = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const other = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const passkeyId = await createPasskey(owner.userId, "Old name");
    await createPasskey(other.userId, "Other user's key");

    const listResponse = await exports.default.fetch(
      new Request("http://localhost:5173/passkey/list-user-passkeys", {
        headers: owner.headers,
      }),
    );
    expect(listResponse.status).toBe(200);
    const passkeys = (await listResponse.json()) as Array<{
      id: string;
      name: string;
      userId: string;
    }>;
    expect(passkeys).toHaveLength(1);
    expect(passkeys[0]).toMatchObject({
      id: passkeyId,
      name: "Old name",
      userId: owner.userId,
    });

    const updateResponse = await exports.default.fetch(
      new Request("http://localhost:5173/passkey/update-passkey", {
        method: "POST",
        headers: owner.headers,
        body: JSON.stringify({ id: passkeyId, name: "Laptop key" }),
      }),
    );
    expect(updateResponse.status).toBe(200);
    expect(
      await env.PG72_ID_DB.prepare("SELECT name FROM passkey WHERE id = ?")
        .bind(passkeyId)
        .first<{ name: string }>(),
    ).toEqual({ name: "Laptop key" });
  });

  it("deletes an owned passkey and rejects cross-account or cross-origin deletion", async () => {
    const owner = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const other = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const ownedPasskeyId = await createPasskey(owner.userId, "Owned key");
    const otherPasskeyId = await createPasskey(other.userId, "Other key");

    const forbiddenResponse = await exports.default.fetch(
      new Request("http://localhost:5173/passkey/delete-passkey", {
        method: "POST",
        headers: owner.headers,
        body: JSON.stringify({ id: otherPasskeyId }),
      }),
    );
    expect(forbiddenResponse.status).toBe(404);

    const crossOriginHeaders = new Headers(owner.headers);
    crossOriginHeaders.set("Origin", "https://attacker.example");
    const crossOriginResponse = await exports.default.fetch(
      new Request("http://localhost:5173/passkey/delete-passkey", {
        method: "POST",
        headers: crossOriginHeaders,
        body: JSON.stringify({ id: ownedPasskeyId }),
      }),
    );
    expect(crossOriginResponse.status).toBe(403);

    const deleteResponse = await exports.default.fetch(
      new Request("http://localhost:5173/passkey/delete-passkey", {
        method: "POST",
        headers: owner.headers,
        body: JSON.stringify({ id: ownedPasskeyId }),
      }),
    );
    expect(deleteResponse.status).toBe(200);
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM passkey WHERE id = ?")
        .bind(ownedPasskeyId)
        .first(),
    ).toBeNull();
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM passkey WHERE id = ?")
        .bind(otherPasskeyId)
        .first(),
    ).not.toBeNull();
  });

  it("requires a fresh session to delete the last passkey", async () => {
    const owner = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const passkeyId = await createPasskey(owner.userId, "Last key");
    await env.PG72_ID_DB.prepare(
      "UPDATE session SET createdAt = ? WHERE id = ?",
    )
      .bind(new Date(Date.now() - 11 * 60 * 1000).toISOString(), owner.sessionId)
      .run();

    const staleResponse = await exports.default.fetch(
      new Request("http://localhost:5173/passkey/delete-passkey", {
        method: "POST",
        headers: owner.headers,
        body: JSON.stringify({ id: passkeyId }),
      }),
    );
    expect(staleResponse.status).toBe(403);
    expect(await staleResponse.json()).toMatchObject({
      code: "SESSION_NOT_FRESH",
      error: "fresh_session_required",
    });
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM passkey WHERE id = ?")
        .bind(passkeyId)
        .first(),
    ).not.toBeNull();

    await env.PG72_ID_DB.prepare(
      "UPDATE session SET createdAt = ? WHERE id = ?",
    )
      .bind(new Date().toISOString(), owner.sessionId)
      .run();
    const freshResponse = await exports.default.fetch(
      new Request("http://localhost:5173/passkey/delete-passkey", {
        method: "POST",
        headers: owner.headers,
        body: JSON.stringify({ id: passkeyId }),
      }),
    );
    expect(freshResponse.status).toBe(200);
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM passkey WHERE id = ?")
        .bind(passkeyId)
        .first(),
    ).toBeNull();
  });

  it("rejects invalid invitation normalization at the database boundary", async () => {
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO invitation
          (id, email_normalized, role, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
        .bind(
          crypto.randomUUID(),
          "Friend@Example.com",
          "user",
          "2099-01-01T00:00:00.000Z",
          "2026-07-15T00:00:00.000Z",
        )
        .run(),
    ).rejects.toThrow();
  });

  it("rejects invalid user roles at the database boundary", async () => {
    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO user
          (id, name, email, emailVerified, createdAt, updatedAt, role, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          crypto.randomUUID(),
          "Invalid Role",
          "invalid-role@example.com",
          1,
          "2026-07-15T00:00:00.000Z",
          "2026-07-15T00:00:00.000Z",
          "owner",
          "active",
        )
        .run(),
    ).rejects.toThrow("invalid user role");
  });

  it("fails closed when production issuer or passkey settings drift", () => {
    const invalidEnv = {
      ...env,
      ENVIRONMENT: "production",
      AUTH_BASE_URL: "https://preview.example.com",
      PASSKEY_ORIGIN: "https://preview.example.com",
      PASSKEY_RP_ID: "example.com",
    };

    expect(() => readRuntimeConfig(invalidEnv)).toThrow(
      "Production AUTH_BASE_URL must be https://sso.pg72.tw",
    );
  });

  it("requires a bootstrap administrator binding", () => {
    expect(() =>
      readRuntimeConfig({ ...env, BOOTSTRAP_ADMIN_EMAIL: "" }),
    ).toThrow("Missing required binding: BOOTSTRAP_ADMIN_EMAIL");
  });

  it("recovers after aborted auth requests in the same isolate", async () => {
    const aborted = Array.from({ length: 12 }, async () => {
      const controller = new AbortController();
      controller.abort();
      return exports.default.fetch(
        new Request(
          "http://localhost:5173/.well-known/openid-configuration",
          { signal: controller.signal },
        ),
      );
    });

    await Promise.allSettled(aborted);
    const response = await exports.default.fetch(
      "http://localhost:5173/.well-known/openid-configuration",
    );
    expect(response.status).toBe(200);
  });
});
