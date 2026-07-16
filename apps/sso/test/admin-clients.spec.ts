import { env, exports } from "cloudflare:workers";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { app } from "../worker/index";
import { validRedirectUri } from "../worker/admin-clients";
import { createAuthenticatedUser, sha256Base64Url } from "./helpers";

const CLIENTS_URL = "http://localhost:5173/api/admin/clients";

interface CreatedClientResponse {
  client: {
    clientId: string;
    name: string;
    public: boolean;
    disabled: boolean;
    scopes: string[];
    redirectUris: string[];
    grantTypes: string[];
    tokenEndpointAuthMethod: string | null;
    hasSecret: boolean;
    trusted: boolean;
  };
  clientSecret?: string;
}

interface ClientRow {
  clientId: string;
  clientSecret: string | null;
  disabled: number;
  skipConsent: number;
  requirePKCE: number;
  public: number;
  tokenEndpointAuthMethod: string;
  scopes: string;
  grantTypes: string;
  redirectUris: string;
}

async function createAdmin() {
  return createAuthenticatedUser(`${crypto.randomUUID()}@example.com`, "admin", {
    passkeyStepUp: true,
  });
}

function createClientRequest(
  headers: Headers,
  body: Record<string, unknown>,
): Request {
  return new Request(CLIENTS_URL, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

async function createClient(
  headers: Headers,
  body: Record<string, unknown>,
): Promise<{ status: number; payload: CreatedClientResponse }> {
  const response = await exports.default.fetch(
    createClientRequest(headers, body),
  );
  return {
    status: response.status,
    payload: (await response.json()) as CreatedClientResponse,
  };
}

function confidentialClientBody(clientId: string): Record<string, unknown> {
  return {
    clientId,
    name: "Admin API Test Client",
    developerName: "PG72 Platform Team",
    redirectUris: [`https://${clientId}.example/callback`],
    scopes: ["openid", "profile", "email", "offline_access"],
    grantTypes: ["authorization_code", "refresh_token"],
  };
}

async function mintAuthorizationCode(
  userHeaders: Headers,
  clientId: string,
  redirectUri: string,
  codeChallenge: string,
): Promise<string> {
  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid profile email",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state: "B".repeat(43),
    nonce: "C".repeat(43),
  });
  const authorizeResponse = await exports.default.fetch(
    new Request(`http://localhost:5173/oauth2/authorize?${query}`, {
      headers: userHeaders,
      redirect: "manual",
    }),
  );
  expect(authorizeResponse.status).toBe(302);
  const consentLocation = new URL(
    authorizeResponse.headers.get("location") ?? "",
    "http://localhost:5173",
  );

  // When consent was already granted, authorize redirects straight back to
  // the relying party with a code.
  if (`${consentLocation.origin}${consentLocation.pathname}` === redirectUri) {
    const directCode = consentLocation.searchParams.get("code");
    expect(directCode).toBeTruthy();
    return directCode ?? "";
  }
  expect(consentLocation.pathname).toBe("/consent");

  const consentHeaders = new Headers(userHeaders);
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
  return code ?? "";
}

async function fetchClientRow(clientId: string): Promise<ClientRow | null> {
  return env.PG72_ID_DB.prepare(
    `SELECT clientId, clientSecret, disabled, skipConsent, requirePKCE,
            public, tokenEndpointAuthMethod, scopes, grantTypes, redirectUris
       FROM oauthClient
      WHERE clientId = ?
      LIMIT 1`,
  )
    .bind(clientId)
    .first<ClientRow>();
}

function interposeAfterManagedClientLoad(
  afterLoad: () => Promise<void>,
): { database: D1Database; wasIntercepted: () => boolean } {
  const realDatabase = env.PG72_ID_DB;
  let intercepted = false;

  const wrapManagedSelect = (
    statement: D1PreparedStatement,
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapManagedSelect(target.bind(...values));
        }
        if (property === "first") {
          return async (columnName?: string) => {
            const result =
              columnName === undefined
                ? await target.first()
                : await target.first(columnName);
            if (!intercepted && result !== null) {
              intercepted = true;
              await afterLoad();
            }
            return result;
          };
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });

  const database = new Proxy(realDatabase, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => {
          const statement = target.prepare(query);
          return query.includes(
            "SELECT id, ownerUserId, public, clientSecret, tos, policy, metadata",
          )
            ? wrapManagedSelect(statement)
            : statement;
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });

  return { database, wasIntercepted: () => intercepted };
}

async function insertReplacementClient(
  clientId: string,
  clientRowId: string,
  ownerUserId: string,
): Promise<void> {
  const now = new Date().toISOString();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO oauthClient (
      id, clientId, clientSecret, disabled, skipConsent, enableEndSession,
      subjectType, scopes, createdAt, updatedAt, name, redirectUris,
      postLogoutRedirectUris, tokenEndpointAuthMethod, grantTypes,
      responseTypes, public, type, requirePKCE, ownerUserId, metadata
    ) VALUES (?, ?, ?, 0, 0, 0, 'public', '["openid"]', ?, ?, ?, ?, NULL,
              'client_secret_post', '["authorization_code"]', '["code"]',
              0, 'web', 1, ?, ?)`,
  )
    .bind(
      clientRowId,
      clientId,
      "replacement-secret-hash",
      now,
      now,
      "Replacement Client",
      JSON.stringify([`https://${clientId}.example/replacement-callback`]),
      ownerUserId,
      JSON.stringify({ developer_name: "Replacement Owner" }),
    )
    .run();
}

describe("Admin OAuth client management", () => {
  it("requires an authenticated session", async () => {
    const listResponse = await exports.default.fetch(CLIENTS_URL);
    expect(listResponse.status).toBe(401);
    expect(await listResponse.json()).toEqual({ error: "unauthorized" });

    const createResponse = await exports.default.fetch(
      createClientRequest(
        new Headers({
          "Content-Type": "application/json",
          Origin: "http://localhost:5173",
        }),
        confidentialClientBody(`unauth-${crypto.randomUUID()}`),
      ),
    );
    expect(createResponse.status).toBe(401);
    expect(await createResponse.json()).toEqual({ error: "unauthorized" });
  });

  it("rejects non-admin users", async () => {
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "user",
    );

    const listResponse = await exports.default.fetch(
      new Request(CLIENTS_URL, { headers }),
    );
    expect(listResponse.status).toBe(403);
    expect(await listResponse.json()).toEqual({ error: "forbidden" });

    const clientId = `non-admin-${crypto.randomUUID()}`;
    const createResponse = await exports.default.fetch(
      createClientRequest(headers, confidentialClientBody(clientId)),
    );
    expect(createResponse.status).toBe(403);
    expect(await fetchClientRow(clientId)).toBeNull();
  });

  it("rejects cross-origin client administration", async () => {
    const { headers } = await createAdmin();
    headers.set("Origin", "https://attacker.example");

    const clientId = `cross-origin-${crypto.randomUUID()}`;
    const createResponse = await exports.default.fetch(
      createClientRequest(headers, confidentialClientBody(clientId)),
    );
    expect(createResponse.status).toBe(403);
    expect(await createResponse.json()).toEqual({ error: "invalid_origin" });
    expect(await fetchClientRow(clientId)).toBeNull();

    const listResponse = await exports.default.fetch(
      new Request(CLIENTS_URL, { headers }),
    );
    expect(listResponse.status).toBe(403);
    expect(await listResponse.json()).toEqual({ error: "invalid_origin" });
  });

  it("allows same-origin reads without an Origin header", async () => {
    const { headers } = await createAdmin();
    headers.delete("Origin");

    const response = await exports.default.fetch(
      new Request(CLIENTS_URL, { headers }),
    );
    expect(response.status).toBe(200);
  });

  it("rejects wildcard, malformed, and credentialed redirect URIs", async () => {
    const { headers } = await createAdmin();

    for (const redirectUri of [
      "https://copy.pg72.tw/*",
      "https://*.pg72.tw/callback",
      "not-a-url",
      "https://user:secret@copy.pg72.tw/callback",
      "https://copy.pg72.tw/callback#fragment",
      "javascript:alert(1)",
    ]) {
      const clientId = `bad-redirect-${crypto.randomUUID()}`;
      const { status, payload } = await createClient(headers, {
        ...confidentialClientBody(clientId),
        redirectUris: [redirectUri],
      });
      expect(status).toBe(400);
      expect(payload).toMatchObject({ error: "invalid_redirect_uri" });
      expect(await fetchClientRow(clientId)).toBeNull();
    }
  });

  it("rejects HTTP redirect URIs in production mode", async () => {
    expect(validRedirectUri("http://copy.pg72.tw/callback", "production")).toBe(
      false,
    );
    expect(validRedirectUri("http://localhost:5174/callback", "production")).toBe(
      false,
    );
    expect(validRedirectUri("https://copy.pg72.tw/callback", "production")).toBe(
      true,
    );
    expect(validRedirectUri("http://localhost:5174/callback", "development")).toBe(
      true,
    );

    const productionEnv = {
      ...env,
      ENVIRONMENT: "production",
      AUTH_BASE_URL: "https://sso.pg72.tw",
      PASSKEY_ORIGIN: "https://sso.pg72.tw",
      PASSKEY_RP_ID: "sso.pg72.tw",
    } as typeof env;
    const { headers } = await createAdmin();
    headers.set("Origin", "https://sso.pg72.tw");

    const rejectedClientId = `prod-http-${crypto.randomUUID()}`;
    const rejectionCtx = createExecutionContext();
    const rejection = await app.fetch(
      new Request("https://sso.pg72.tw/api/admin/clients", {
        method: "POST",
        headers,
        body: JSON.stringify({
          ...confidentialClientBody(rejectedClientId),
          redirectUris: ["http://copy.pg72.tw/callback"],
        }),
      }),
      productionEnv,
      rejectionCtx,
    );
    await waitOnExecutionContext(rejectionCtx);
    expect(rejection.status).toBe(400);
    expect(await rejection.json()).toMatchObject({
      error: "invalid_redirect_uri",
    });
    expect(await fetchClientRow(rejectedClientId)).toBeNull();

    const acceptedClientId = `prod-https-${crypto.randomUUID()}`;
    const acceptanceCtx = createExecutionContext();
    const acceptance = await app.fetch(
      new Request("https://sso.pg72.tw/api/admin/clients", {
        method: "POST",
        headers,
        body: JSON.stringify(confidentialClientBody(acceptedClientId)),
      }),
      productionEnv,
      acceptanceCtx,
    );
    await waitOnExecutionContext(acceptanceCtx);
    expect(acceptance.status).toBe(201);
    expect(await fetchClientRow(acceptedClientId)).not.toBeNull();
  });

  it("rejects clients that attempt to skip consent", async () => {
    const { headers } = await createAdmin();

    for (const skipConsent of [1, true, "1"]) {
      const clientId = `skip-consent-${crypto.randomUUID()}`;
      const { status, payload } = await createClient(headers, {
        ...confidentialClientBody(clientId),
        skipConsent,
      });
      expect(status).toBe(400);
      expect(payload).toMatchObject({ error: "skip_consent_not_allowed" });
      expect(await fetchClientRow(clientId)).toBeNull();
    }
  });

  it("rejects scopes and grants outside the allowed contract", async () => {
    const { headers } = await createAdmin();
    const base = confidentialClientBody(`contract-${crypto.randomUUID()}`);

    const invalidScopes = await createClient(headers, {
      ...base,
      scopes: ["openid", "admin"],
    });
    expect(invalidScopes.status).toBe(400);
    expect(invalidScopes.payload).toMatchObject({ error: "invalid_scopes" });

    const missingOpenid = await createClient(headers, {
      ...base,
      scopes: ["profile", "email"],
    });
    expect(missingOpenid.status).toBe(400);
    expect(missingOpenid.payload).toMatchObject({ error: "invalid_scopes" });

    const invalidGrant = await createClient(headers, {
      ...base,
      grantTypes: ["authorization_code", "client_credentials"],
    });
    expect(invalidGrant.status).toBe(400);
    expect(invalidGrant.payload).toMatchObject({ error: "invalid_grant_types" });

    const missingAuthorizationCode = await createClient(headers, {
      ...base,
      grantTypes: ["refresh_token"],
    });
    expect(missingAuthorizationCode.status).toBe(400);
    expect(missingAuthorizationCode.payload).toMatchObject({
      error: "invalid_grant_types",
    });

    const refreshWithoutOffline = await createClient(headers, {
      ...base,
      scopes: ["openid", "profile", "email"],
      grantTypes: ["authorization_code", "refresh_token"],
    });
    expect(refreshWithoutOffline.status).toBe(400);
    expect(refreshWithoutOffline.payload).toMatchObject({
      error: "refresh_token_requires_offline_access",
    });

    const inconsistentAuthMethod = await createClient(headers, {
      ...base,
      public: true,
      tokenEndpointAuthMethod: "client_secret_post",
    });
    expect(inconsistentAuthMethod.status).toBe(400);
    expect(inconsistentAuthMethod.payload).toMatchObject({
      error: "invalid_token_endpoint_auth_method",
    });
  });

  it("creates a confidential client with a hashed one-time secret", async () => {
    const { headers, userId } = await createAdmin();
    const clientId = `pg72-copy-${crypto.randomUUID()}`;

    const { status, payload } = await createClient(
      headers,
      confidentialClientBody(clientId),
    );
    expect(status).toBe(201);
    expect(payload.client).toMatchObject({
      clientId,
      public: false,
      disabled: false,
      hasSecret: true,
      trusted: false,
      developerName: "PG72 Platform Team",
      tokenEndpointAuthMethod: "client_secret_post",
      scopes: ["openid", "profile", "email", "offline_access"],
      grantTypes: ["authorization_code", "refresh_token"],
    });
    expect(payload.clientSecret).toMatch(/^pg72_cs_/);

    const secretSuffix = (payload.clientSecret ?? "").slice("pg72_cs_".length);
    const row = await fetchClientRow(clientId);
    expect(row).toMatchObject({
      clientId,
      disabled: 0,
      skipConsent: 0,
      requirePKCE: 1,
      public: 0,
      tokenEndpointAuthMethod: "client_secret_post",
    });
    // Stored in the oauth-provider "hashed" format: unpadded base64url SHA-256
    // of the secret without its pg72_cs_ prefix.
    expect(row?.clientSecret).toBe(await sha256Base64Url(secretSuffix));
    expect(row?.clientSecret).not.toContain(secretSuffix);

    const audit = await env.PG72_ID_DB.prepare(
      `SELECT outcome, subject_id FROM audit_event
        WHERE event_type = 'oauth_client.created' AND client_id = ?`,
    )
      .bind(clientId)
      .first<{ outcome: string; subject_id: string }>();
    expect(audit).toEqual({ outcome: "success", subject_id: userId });

    const listResponse = await exports.default.fetch(
      new Request(CLIENTS_URL, { headers }),
    );
    expect(listResponse.status).toBe(200);
    const listBody = await listResponse.text();
    const listed = (JSON.parse(listBody) as {
      clients: Array<{ clientId: string; hasSecret: boolean }>;
    }).clients.find((client) => client.clientId === clientId);
    expect(listed).toMatchObject({ clientId, hasSecret: true });
    // The plaintext secret and its stored hash never appear in list output.
    expect(listBody).not.toContain(secretSuffix);
    expect(listBody).not.toContain(row?.clientSecret ?? "impossible-value");

    const duplicate = await createClient(headers, confidentialClientBody(clientId));
    expect(duplicate.status).toBe(409);
    expect(duplicate.payload).toMatchObject({ error: "client_exists" });

    // Existence check: the created client resolves through the authorize
    // endpoint and redirects an unauthenticated browser to sign-in.
    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: `https://${clientId}.example/callback`,
      response_type: "code",
      scope: "openid profile email",
      code_challenge: "A".repeat(43),
      code_challenge_method: "S256",
      state: "B".repeat(43),
      nonce: "C".repeat(43),
    });
    const authorizeResponse = await exports.default.fetch(
      new Request(`http://localhost:5173/oauth2/authorize?${query}`, {
        headers: { "Sec-Fetch-Mode": "cors" },
        redirect: "manual",
      }),
    );
    expect(authorizeResponse.status).toBe(302);
    const location = new URL(authorizeResponse.headers.get("location") ?? "");
    expect(location.pathname).toBe("/sign-in");
    expect(location.searchParams.get("client_id")).toBe(clientId);
  });

  it("exchanges a code with client_secret_post for an encoded client id", async () => {
    const { headers } = await createAdmin();
    const clientId = `pg72-post_${crypto.randomUUID()}`;
    const redirectUri = `https://${clientId}.example/callback`;
    const verifier = "P".repeat(43);
    const challenge = await sha256Base64Url(verifier);

    const created = await createClient(
      headers,
      confidentialClientBody(clientId),
    );
    expect(created.status).toBe(201);
    expect(created.payload.client.tokenEndpointAuthMethod).toBe(
      "client_secret_post",
    );
    const clientSecret = created.payload.clientSecret ?? "";
    expect(clientSecret).toMatch(/^pg72_cs_/);

    const code = await mintAuthorizationCode(
      headers,
      clientId,
      redirectUri,
      challenge,
    );
    const tokenResponse = await exports.default.fetch(
      new Request("http://localhost:5173/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri,
          code_verifier: verifier,
          client_id: clientId,
          client_secret: clientSecret,
        }),
      }),
    );

    expect(tokenResponse.status).toBe(200);
    expect(await tokenResponse.json()).toMatchObject({
      token_type: "Bearer",
    });
  });

  it("creates a public client without a secret", async () => {
    const { headers } = await createAdmin();
    const clientId = `public-${crypto.randomUUID()}`;

    const { status, payload } = await createClient(headers, {
      clientId,
      name: "Public Test Client",
      developerName: "PG72 Platform Team",
      redirectUris: ["http://localhost:5174/callback"],
      public: true,
    });
    expect(status).toBe(201);
    expect(payload.clientSecret).toBeUndefined();
    expect(payload.client).toMatchObject({
      clientId,
      public: true,
      hasSecret: false,
      tokenEndpointAuthMethod: "none",
    });

    const row = await fetchClientRow(clientId);
    expect(row).toMatchObject({
      clientSecret: null,
      public: 1,
      requirePKCE: 1,
      skipConsent: 0,
      tokenEndpointAuthMethod: "none",
    });

    const rotateResponse = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${clientId}/rotate-secret`, {
        method: "POST",
        headers,
      }),
    );
    expect(rotateResponse.status).toBe(400);
    expect(await rotateResponse.json()).toMatchObject({
      error: "public_client_has_no_secret",
    });
  });

  it("rotates a confidential client secret and invalidates the old one", async () => {
    const { headers } = await createAdmin();
    const clientId = `rotate-${crypto.randomUUID()}`;
    const redirectUri = `https://${clientId}.example/callback`;
    const codeVerifier = "V".repeat(43);
    const codeChallenge = await sha256Base64Url(codeVerifier);

    const created = await createClient(headers, confidentialClientBody(clientId));
    expect(created.status).toBe(201);
    const oldSecret = created.payload.clientSecret ?? "";
    const oldStored = (await fetchClientRow(clientId))?.clientSecret;

    const exchange = (secret: string, code: string) =>
      exports.default.fetch(
        new Request("http://localhost:5173/oauth2/token", {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: redirectUri,
            code_verifier: codeVerifier,
            client_id: clientId,
            client_secret: secret,
          }),
        }),
      );

    const rotateResponse = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${clientId}/rotate-secret`, {
        method: "POST",
        headers,
      }),
    );
    expect(rotateResponse.status).toBe(200);
    const rotation = (await rotateResponse.json()) as {
      clientId: string;
      clientSecret: string;
    };
    expect(rotation.clientId).toBe(clientId);
    expect(rotation.clientSecret).toMatch(/^pg72_cs_/);
    expect(rotation.clientSecret).not.toBe(oldSecret);

    const newStored = (await fetchClientRow(clientId))?.clientSecret;
    expect(newStored).toBe(
      await sha256Base64Url(rotation.clientSecret.slice("pg72_cs_".length)),
    );
    expect(newStored).not.toBe(oldStored);

    // With a real authorization code, the old secret now fails client
    // authentication at the token endpoint.
    const firstCode = await mintAuthorizationCode(
      headers,
      clientId,
      redirectUri,
      codeChallenge,
    );
    const oldSecretResponse = await exchange(oldSecret, firstCode);
    expect(oldSecretResponse.status).toBe(401);
    expect(await oldSecretResponse.json()).toMatchObject({
      error: "invalid_client",
      error_description: "invalid client_secret",
    });

    // The rotated secret completes the exchange (the first code was consumed
    // by the rejected attempt, so a fresh one is minted).
    const secondCode = await mintAuthorizationCode(
      headers,
      clientId,
      redirectUri,
      codeChallenge,
    );
    const newSecretResponse = await exchange(rotation.clientSecret, secondCode);
    expect(newSecretResponse.status).toBe(200);
    expect(await newSecretResponse.json()).toMatchObject({
      token_type: "Bearer",
    });

    const audit = await env.PG72_ID_DB.prepare(
      `SELECT outcome FROM audit_event
        WHERE event_type = 'oauth_client.secret_rotated' AND client_id = ?`,
    )
      .bind(clientId)
      .first();
    expect(audit).toEqual({ outcome: "success" });
  });

  it("disables a client, revokes its tokens, and can re-enable it", async () => {
    const { headers, userId } = await createAdmin();
    const clientId = `disable-${crypto.randomUUID()}`;
    const redirectUri = `https://${clientId}.example/callback`;

    const created = await createClient(headers, confidentialClientBody(clientId));
    expect(created.status).toBe(201);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString();
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthConsent (id, clientId, userId, scopes, createdAt, updatedAt)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        clientId,
        userId,
        '["openid","email"]',
        now.toISOString(),
        now.toISOString(),
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthAccessToken (id, token, clientId, userId, expiresAt, createdAt, scopes)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        crypto.randomUUID(),
        clientId,
        userId,
        expiresAt,
        now.toISOString(),
        '["openid","email"]',
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthRefreshToken (id, token, clientId, userId, expiresAt, createdAt, scopes)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        crypto.randomUUID(),
        clientId,
        userId,
        expiresAt,
        now.toISOString(),
        '["openid","email"]',
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt)
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
    ]);

    const disableResponse = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${clientId}/status`, {
        method: "POST",
        headers,
        body: JSON.stringify({ disabled: true }),
      }),
    );
    expect(disableResponse.status).toBe(200);
    expect(await disableResponse.json()).toMatchObject({
      clientId,
      disabled: true,
    });

    const afterDisable = await env.PG72_ID_DB.prepare(
      `SELECT
        (SELECT disabled FROM oauthClient WHERE clientId = ?1) AS disabled,
        (SELECT COUNT(*) FROM oauthAccessToken WHERE clientId = ?1) AS access_tokens,
        (SELECT COUNT(*) FROM oauthRefreshToken
          WHERE clientId = ?1 AND revoked IS NULL) AS live_refresh_tokens,
        (SELECT COUNT(*) FROM oauthConsent WHERE clientId = ?1) AS consents,
        (SELECT COUNT(*) FROM verification
          WHERE CASE WHEN json_valid(value) THEN
            json_extract(value, '$.type') = 'authorization_code'
            AND json_extract(value, '$.query.client_id') = ?1
          ELSE 0 END) AS authorization_codes`,
    )
      .bind(clientId)
      .first();
    expect(afterDisable).toEqual({
      disabled: 1,
      access_tokens: 0,
      live_refresh_tokens: 0,
      consents: 1,
      authorization_codes: 0,
    });

    // The authorize endpoint refuses disabled clients with an error redirect
    // instead of starting a sign-in or consent flow.
    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "openid profile email",
      code_challenge: "A".repeat(43),
      code_challenge_method: "S256",
      state: "B".repeat(43),
      nonce: "C".repeat(43),
    });
    const disabledAuthorize = await exports.default.fetch(
      new Request(`http://localhost:5173/oauth2/authorize?${query}`, {
        headers: { "Sec-Fetch-Mode": "cors" },
        redirect: "manual",
      }),
    );
    expect(disabledAuthorize.status).toBe(302);
    const disabledLocation = new URL(
      disabledAuthorize.headers.get("location") ?? "",
      "http://localhost:5173",
    );
    expect(disabledLocation.pathname).not.toBe("/sign-in");
    expect(disabledLocation.pathname).not.toBe("/consent");
    expect(disabledAuthorize.headers.get("location")).toContain(
      "client_disabled",
    );

    const enableResponse = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${clientId}/status`, {
        method: "POST",
        headers,
        body: JSON.stringify({ disabled: false }),
      }),
    );
    expect(enableResponse.status).toBe(200);
    const enabledRow = await fetchClientRow(clientId);
    expect(enabledRow?.disabled).toBe(0);

    const auditEvents = await env.PG72_ID_DB.prepare(
      `SELECT event_type FROM audit_event
        WHERE client_id = ?
          AND event_type IN ('oauth_client.disabled', 'oauth_client.enabled')
        ORDER BY occurred_at ASC`,
    )
      .bind(clientId)
      .all<{ event_type: string }>();
    expect(auditEvents.results.map((event) => event.event_type)).toEqual([
      "oauth_client.disabled",
      "oauth_client.enabled",
    ]);
  });

  it("deletes a client together with its tokens and consents", async () => {
    const { headers, userId } = await createAdmin();
    const clientId = `delete-${crypto.randomUUID()}`;

    const created = await createClient(headers, confidentialClientBody(clientId));
    expect(created.status).toBe(201);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString();
    const refreshTokenId = crypto.randomUUID();
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthConsent (id, clientId, userId, scopes, createdAt, updatedAt)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        clientId,
        userId,
        '["openid","email"]',
        now.toISOString(),
        now.toISOString(),
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthRefreshToken (id, token, clientId, userId, expiresAt, createdAt, scopes)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        refreshTokenId,
        crypto.randomUUID(),
        clientId,
        userId,
        expiresAt,
        now.toISOString(),
        '["openid","email"]',
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthAccessToken
          (id, token, clientId, userId, refreshId, expiresAt, createdAt, scopes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        crypto.randomUUID(),
        clientId,
        userId,
        refreshTokenId,
        expiresAt,
        now.toISOString(),
        '["openid","email"]',
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt)
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
    ]);

    const deleteResponse = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${clientId}`, {
        method: "DELETE",
        headers,
      }),
    );
    expect(deleteResponse.status).toBe(200);
    expect(await deleteResponse.json()).toEqual({ deleted: true, clientId });

    const remaining = await env.PG72_ID_DB.prepare(
      `SELECT
        (SELECT COUNT(*) FROM oauthClient WHERE clientId = ?1) AS clients,
        (SELECT COUNT(*) FROM oauthConsent WHERE clientId = ?1) AS consents,
        (SELECT COUNT(*) FROM oauthAccessToken WHERE clientId = ?1) AS access_tokens,
        (SELECT COUNT(*) FROM oauthRefreshToken WHERE clientId = ?1) AS refresh_tokens,
        (SELECT COUNT(*) FROM verification
          WHERE CASE WHEN json_valid(value) THEN
            json_extract(value, '$.type') = 'authorization_code'
            AND json_extract(value, '$.query.client_id') = ?1
          ELSE 0 END) AS authorization_codes`,
    )
      .bind(clientId)
      .first();
    expect(remaining).toEqual({
      clients: 0,
      consents: 0,
      access_tokens: 0,
      refresh_tokens: 0,
      authorization_codes: 0,
    });

    const audit = await env.PG72_ID_DB.prepare(
      `SELECT outcome FROM audit_event
        WHERE event_type = 'oauth_client.deleted' AND client_id = ?`,
    )
      .bind(clientId)
      .first();
    expect(audit).toEqual({ outcome: "success" });

    const repeatedDelete = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${clientId}`, {
        method: "DELETE",
        headers,
      }),
    );
    expect(repeatedDelete.status).toBe(404);
  });

  it("rejects a stale developer mutation after the owner account is deleted", async () => {
    const developer = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "developer",
      { passkeyStepUp: true },
    );
    const clientId = `orphan-race-${crypto.randomUUID()}`;
    expect(
      (await createClient(developer.headers, confidentialClientBody(clientId)))
        .status,
    ).toBe(201);

    const original = await env.PG72_ID_DB.prepare(
      "SELECT id FROM oauthClient WHERE clientId = ?",
    )
      .bind(clientId)
      .first<{ id: string }>();
    expect(original?.id).toBeTruthy();

    const interposed = interposeAfterManagedClientLoad(async () => {
      await env.PG72_ID_DB.prepare("DELETE FROM user WHERE id = ?")
        .bind(developer.userId)
        .run();
    });
    const requestEnv = {
      ...env,
      PG72_ID_DB: interposed.database,
    } as Env;
    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${CLIENTS_URL}/${clientId}/status`, {
        method: "POST",
        headers: developer.headers,
        body: JSON.stringify({ disabled: true }),
      }),
      requestEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(interposed.wasIntercepted()).toBe(true);
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      error: "management_state_changed",
    });
    const after = await env.PG72_ID_DB.prepare(
      "SELECT id, ownerUserId, disabled FROM oauthClient WHERE clientId = ?",
    )
      .bind(clientId)
      .first<{ id: string; ownerUserId: string | null; disabled: number }>();
    expect(after).toEqual({
      id: original?.id,
      ownerUserId: null,
      disabled: 0,
    });
    const audit = await env.PG72_ID_DB.prepare(
      `SELECT COUNT(*) AS count
         FROM audit_event
        WHERE event_type = 'oauth_client.disabled' AND client_id = ?`,
    )
      .bind(clientId)
      .first<{ count: number }>();
    expect(audit?.count).toBe(0);
  });

  it("does not let a stale admin request delete a replacement client", async () => {
    const admin = await createAdmin();
    const replacementOwner = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "developer",
    );
    const clientId = `replacement-race-${crypto.randomUUID()}`;
    expect(
      (await createClient(admin.headers, confidentialClientBody(clientId))).status,
    ).toBe(201);

    const original = await env.PG72_ID_DB.prepare(
      "SELECT id FROM oauthClient WHERE clientId = ?",
    )
      .bind(clientId)
      .first<{ id: string }>();
    const replacementId = crypto.randomUUID();
    const replacementAccessTokenId = crypto.randomUUID();
    const replacementCodeId = crypto.randomUUID();
    const interposed = interposeAfterManagedClientLoad(async () => {
      await env.PG72_ID_DB.prepare(
        "DELETE FROM oauthClient WHERE clientId = ?",
      )
        .bind(clientId)
        .run();
      await insertReplacementClient(
        clientId,
        replacementId,
        replacementOwner.userId,
      );

      const now = new Date();
      const expiresAt = new Date(
        now.getTime() + 60 * 60 * 1000,
      ).toISOString();
      await env.PG72_ID_DB.batch([
        env.PG72_ID_DB.prepare(
          `INSERT INTO oauthAccessToken
            (id, token, clientId, userId, expiresAt, createdAt, scopes)
           VALUES (?, ?, ?, ?, ?, ?, '["openid"]')`,
        ).bind(
          replacementAccessTokenId,
          crypto.randomUUID(),
          clientId,
          replacementOwner.userId,
          expiresAt,
          now.toISOString(),
        ),
        env.PG72_ID_DB.prepare(
          `INSERT INTO verification
            (id, identifier, value, expiresAt, createdAt, updatedAt)
           VALUES (?, ?, ?, ?, ?, ?)`,
        ).bind(
          replacementCodeId,
          crypto.randomUUID(),
          JSON.stringify({
            type: "authorization_code",
            userId: replacementOwner.userId,
            query: { client_id: clientId },
          }),
          expiresAt,
          now.toISOString(),
          now.toISOString(),
        ),
      ]);
    });
    const requestEnv = {
      ...env,
      PG72_ID_DB: interposed.database,
    } as Env;
    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${CLIENTS_URL}/${clientId}`, {
        method: "DELETE",
        headers: admin.headers,
      }),
      requestEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(interposed.wasIntercepted()).toBe(true);
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      error: "management_state_changed",
    });
    expect(replacementId).not.toBe(original?.id);
    const replacement = await env.PG72_ID_DB.prepare(
      `SELECT id, ownerUserId, disabled, name
         FROM oauthClient
        WHERE clientId = ?`,
    )
      .bind(clientId)
      .first<{
        id: string;
        ownerUserId: string | null;
        disabled: number;
        name: string;
      }>();
    expect(replacement).toEqual({
      id: replacementId,
      ownerUserId: replacementOwner.userId,
      disabled: 0,
      name: "Replacement Client",
    });
    const relatedRows = await env.PG72_ID_DB.prepare(
      `SELECT
        (SELECT COUNT(*) FROM oauthAccessToken WHERE id = ?1) AS access_tokens,
        (SELECT COUNT(*) FROM verification WHERE id = ?2) AS authorization_codes,
        (SELECT COUNT(*) FROM audit_event
          WHERE event_type = 'oauth_client.deleted' AND client_id = ?3) AS audits`,
    )
      .bind(replacementAccessTokenId, replacementCodeId, clientId)
      .first<{
        access_tokens: number;
        authorization_codes: number;
        audits: number;
      }>();
    expect(relatedRows).toEqual({
      access_tokens: 1,
      authorization_codes: 1,
      audits: 0,
    });
  });

  it("requires a developer identity for new clients", async () => {
    const { headers } = await createAdmin();

    for (const developerName of [undefined, "", "   ", 42, "x".repeat(65)]) {
      const clientId = `no-developer-${crypto.randomUUID()}`;
      const body = confidentialClientBody(clientId);
      if (developerName === undefined) {
        delete body.developerName;
      } else {
        body.developerName = developerName;
      }

      const { status, payload } = await createClient(headers, body);
      expect(status).toBe(400);
      expect(payload).toMatchObject({ error: "invalid_developer_name" });
      expect(await fetchClientRow(clientId)).toBeNull();
    }
  });

  it("rejects trust URLs that are not clean HTTPS", async () => {
    const { headers } = await createAdmin();

    const cases: Array<[string, string, string]> = [
      ["privacyPolicyUrl", "http://copy.pg72.tw/privacy", "invalid_privacy_policy_url"],
      ["privacyPolicyUrl", "https://user:secret@copy.pg72.tw/privacy", "invalid_privacy_policy_url"],
      ["privacyPolicyUrl", "javascript:alert(1)", "invalid_privacy_policy_url"],
      ["termsOfServiceUrl", "http://copy.pg72.tw/terms", "invalid_terms_of_service_url"],
      ["termsOfServiceUrl", "not-a-url", "invalid_terms_of_service_url"],
    ];
    for (const [field, value, error] of cases) {
      const clientId = `bad-trust-url-${crypto.randomUUID()}`;
      const { status, payload } = await createClient(headers, {
        ...confidentialClientBody(clientId),
        [field]: value,
      });
      expect(status).toBe(400);
      expect(payload).toMatchObject({ error });
      expect(await fetchClientRow(clientId)).toBeNull();
    }
  });

  it("stores consent trust metadata on creation", async () => {
    const { headers } = await createAdmin();
    const clientId = `trust-create-${crypto.randomUUID()}`;

    const { status, payload } = await createClient(headers, {
      ...confidentialClientBody(clientId),
      developerName: "  PG72 Lab  ",
      privacyPolicyUrl: "https://apps.pg72.tw/privacy",
      termsOfServiceUrl: "https://apps.pg72.tw/terms",
    });
    expect(status).toBe(201);
    expect(payload.client).toMatchObject({
      developerName: "PG72 Lab",
      privacyPolicyUrl: "https://apps.pg72.tw/privacy",
      termsOfServiceUrl: "https://apps.pg72.tw/terms",
    });

    const row = await env.PG72_ID_DB.prepare(
      "SELECT tos, policy, metadata FROM oauthClient WHERE clientId = ?",
    )
      .bind(clientId)
      .first<{ tos: string; policy: string; metadata: string }>();
    expect(row).toMatchObject({
      tos: "https://apps.pg72.tw/terms",
      policy: "https://apps.pg72.tw/privacy",
    });
    expect(JSON.parse(row?.metadata ?? "{}")).toEqual({
      developer_name: "PG72 Lab",
    });

    const listResponse = await exports.default.fetch(
      new Request(CLIENTS_URL, { headers }),
    );
    const listed = ((await listResponse.json()) as {
      clients: Array<{
        clientId: string;
        developerName: string | null;
        privacyPolicyUrl: string | null;
        termsOfServiceUrl: string | null;
      }>;
    }).clients.find((client) => client.clientId === clientId);
    expect(listed).toMatchObject({
      developerName: "PG72 Lab",
      privacyPolicyUrl: "https://apps.pg72.tw/privacy",
      termsOfServiceUrl: "https://apps.pg72.tw/terms",
    });
  });

  it("edits trust fields while preserving unrelated client metadata", async () => {
    const { headers, userId } = await createAdmin();
    const clientId = `trust-edit-${crypto.randomUUID()}`;

    const created = await createClient(headers, confidentialClientBody(clientId));
    expect(created.status).toBe(201);

    // Simulate a client that also stores provider-level metadata, like the
    // diary client's back-channel logout URI.
    await env.PG72_ID_DB.prepare(
      `UPDATE oauthClient
          SET metadata = json_set(metadata, '$.backchannel_logout_uri',
                                  'https://diary.pg72.tw/api/auth/backchannel-logout')
        WHERE clientId = ?`,
    )
      .bind(clientId)
      .run();

    const patchResponse = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${clientId}`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({
          developerName: "PG72 Diary Team",
          privacyPolicyUrl: "https://diary.pg72.tw/privacy",
          termsOfServiceUrl: null,
        }),
      }),
    );
    expect(patchResponse.status).toBe(200);
    expect(await patchResponse.json()).toMatchObject({
      clientId,
      developerName: "PG72 Diary Team",
      privacyPolicyUrl: "https://diary.pg72.tw/privacy",
      termsOfServiceUrl: null,
    });

    const row = await env.PG72_ID_DB.prepare(
      "SELECT tos, policy, metadata FROM oauthClient WHERE clientId = ?",
    )
      .bind(clientId)
      .first<{ tos: string | null; policy: string | null; metadata: string }>();
    expect(row?.tos).toBeNull();
    expect(row?.policy).toBe("https://diary.pg72.tw/privacy");
    expect(JSON.parse(row?.metadata ?? "{}")).toEqual({
      developer_name: "PG72 Diary Team",
      backchannel_logout_uri: "https://diary.pg72.tw/api/auth/backchannel-logout",
    });

    const invalidUpdate = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${clientId}`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ developerName: "" }),
      }),
    );
    expect(invalidUpdate.status).toBe(400);
    expect(await invalidUpdate.json()).toMatchObject({
      error: "invalid_developer_name",
    });

    const crossOriginHeaders = new Headers(headers);
    crossOriginHeaders.set("Origin", "https://attacker.example");
    const crossOrigin = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${clientId}`, {
        method: "PATCH",
        headers: crossOriginHeaders,
        body: JSON.stringify({ developerName: "Attacker" }),
      }),
    );
    expect(crossOrigin.status).toBe(403);

    const audit = await env.PG72_ID_DB.prepare(
      `SELECT outcome, subject_id FROM audit_event
        WHERE event_type = 'oauth_client.trust_updated' AND client_id = ?`,
    )
      .bind(clientId)
      .first<{ outcome: string; subject_id: string }>();
    expect(audit).toEqual({ outcome: "success", subject_id: userId });
  });

  it("refuses trust edits on trusted or unknown clients", async () => {
    const { headers } = await createAdmin();

    const trusted = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/pg72-test-rp`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ developerName: "Attacker" }),
      }),
    );
    expect(trusted.status).toBe(409);
    expect(await trusted.json()).toEqual({ error: "trusted_client_locked" });

    const missing = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/does-not-exist-${Date.now()}`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ developerName: "Nobody" }),
      }),
    );
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ error: "client_not_found" });
  });

  it("refuses to mutate the cached trusted test RP", async () => {
    const { headers } = await createAdmin();

    for (const request of [
      new Request(`${CLIENTS_URL}/pg72-test-rp/rotate-secret`, {
        method: "POST",
        headers,
      }),
      new Request(`${CLIENTS_URL}/pg72-test-rp/status`, {
        method: "POST",
        headers,
        body: JSON.stringify({ disabled: true }),
      }),
      new Request(`${CLIENTS_URL}/pg72-test-rp`, {
        method: "DELETE",
        headers,
      }),
    ]) {
      const response = await exports.default.fetch(request);
      expect(response.status).toBe(409);
      expect(await response.json()).toEqual({ error: "trusted_client_locked" });
    }

    const creation = await createClient(headers, {
      ...confidentialClientBody("pg72-test-rp"),
      clientId: "pg72-test-rp",
    });
    expect(creation.status).toBe(409);
    expect(creation.payload).toMatchObject({ error: "trusted_client_locked" });
  });
});
