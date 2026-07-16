import { env, exports } from "cloudflare:workers";
import {
  createExecutionContext,
  waitOnExecutionContext,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { app } from "../worker/index";
import {
  createAuthenticatedUser,
  createBootstrapAdmin,
  createSessionFor,
  sha256Base64Url,
} from "./helpers";

const BASE_URL = "http://localhost:5173";
const CLIENTS_URL = `${BASE_URL}/api/admin/clients`;
const USERS_URL = `${BASE_URL}/api/admin/users`;

async function insertProviderAccount(
  userId: string,
  providerId: string,
  accountId = crypto.randomUUID(),
): Promise<D1Result<unknown>> {
  const now = new Date().toISOString();
  return env.PG72_ID_DB.prepare(
    `INSERT INTO account
      (id, accountId, providerId, userId, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?)`,
  )
    .bind(crypto.randomUUID(), accountId, providerId, userId, now, now)
    .run();
}

async function insertPublicClient(
  clientId: string,
  callback: string,
  ownerUserId: string | null = null,
): Promise<void> {
  const now = new Date().toISOString();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO oauthClient (
      id, clientId, clientSecret, disabled, skipConsent, scopes, createdAt,
      updatedAt, name, redirectUris, tokenEndpointAuthMethod, grantTypes,
      responseTypes, public, requirePKCE, ownerUserId
    ) VALUES (?, ?, NULL, 0, 0, '["openid","profile","email"]', ?, ?, ?, ?,
              'none', '["authorization_code"]', '["code"]', 1, 1, ?)`,
  )
    .bind(
      crypto.randomUUID(),
      clientId,
      now,
      now,
      "Restricted Access Test",
      JSON.stringify([callback]),
      ownerUserId,
    )
    .run();
}

function setAccess(
  headers: Headers,
  userId: string,
  restricted: boolean,
): Promise<Response> {
  return exports.default.fetch(
    new Request(`${USERS_URL}/${userId}/access`, {
      method: "POST",
      headers,
      body: JSON.stringify({ restricted }),
    }),
  );
}

function setRole(
  headers: Headers,
  userId: string,
  role: string,
): Promise<Response> {
  return exports.default.fetch(
    new Request(`${USERS_URL}/${userId}/role`, {
      method: "POST",
      headers,
      body: JSON.stringify({ role }),
    }),
  );
}

function interposeAfterTargetLoad(
  afterLoad: () => Promise<void>,
): { database: D1Database; wasIntercepted: () => boolean } {
  const realDatabase = env.PG72_ID_DB;
  let intercepted = false;

  const wrapTargetSelect = (
    statement: D1PreparedStatement,
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapTargetSelect(target.bind(...values));
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
            "SELECT id, email, role, status, accessLevel FROM user",
          )
            ? wrapTargetSelect(statement)
            : statement;
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });

  return { database, wasIntercepted: () => intercepted };
}

describe("restricted account persistence", () => {
  it("defaults existing-style rows to standard and rejects invalid states", async () => {
    const userId = crypto.randomUUID();
    const now = new Date().toISOString();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO user
        (id, name, email, emailVerified, createdAt, updatedAt, role, status)
       VALUES (?, 'Legacy User', ?, 1, ?, ?, 'user', 'active')`,
    )
      .bind(userId, `${userId}@example.com`, now, now)
      .run();

    const row = await env.PG72_ID_DB.prepare(
      "SELECT accessLevel FROM user WHERE id = ?",
    )
      .bind(userId)
      .first<{ accessLevel: string }>();
    expect(row?.accessLevel).toBe("standard");

    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE user SET accessLevel = 'unknown' WHERE id = ?",
      )
        .bind(userId)
        .run(),
    ).rejects.toThrow();

    await expect(
      env.PG72_ID_DB.prepare(
        `INSERT INTO user
          (id, name, email, emailVerified, createdAt, updatedAt, role, status,
           accessLevel)
         VALUES (?, 'Invalid Restricted', ?, 1, ?, ?, 'developer', 'active',
                 'restricted')`,
      )
        .bind(
          crypto.randomUUID(),
          `${crypto.randomUUID()}@example.com`,
          now,
          now,
        )
        .run(),
    ).rejects.toThrow("restricted account cannot hold an elevated role");
  });

  it("allows exactly one initial Google identity under a concurrent replay", async () => {
    const restricted = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "user",
      { accessLevel: "restricted", googleAccount: false },
    );

    const attempts = await Promise.allSettled([
      insertProviderAccount(restricted.userId, "google"),
      insertProviderAccount(restricted.userId, "google"),
    ]);
    expect(attempts.filter(({ status }) => status === "fulfilled")).toHaveLength(
      1,
    );
    expect(attempts.filter(({ status }) => status === "rejected")).toHaveLength(
      1,
    );

    const count = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM account WHERE userId = ?",
    )
      .bind(restricted.userId)
      .first<{ count: number }>();
    expect(count?.count).toBe(1);
    await expect(
      insertProviderAccount(restricted.userId, "google"),
    ).rejects.toThrow("restricted account cannot link providers");
    await expect(
      insertProviderAccount(restricted.userId, "telegram"),
    ).rejects.toThrow("restricted account cannot link providers");
  });

  it("enforces restricted roles and client ownership at the D1 boundary", async () => {
    const restricted = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "user",
      { accessLevel: "restricted" },
    );

    await expect(
      env.PG72_ID_DB.prepare("UPDATE user SET role = 'developer' WHERE id = ?")
        .bind(restricted.userId)
        .run(),
    ).rejects.toThrow("restricted account cannot hold an elevated role");
    await expect(
      insertPublicClient(
        `restricted-owner-${crypto.randomUUID()}`,
        "https://restricted-owner.example/callback",
        restricted.userId,
      ),
    ).rejects.toThrow("client owner is not eligible");
  });
});

describe("restricted account runtime policy", () => {
  it("keeps account access and an ordinary OIDC code flow usable", async () => {
    const restricted = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "user",
      { accessLevel: "restricted" },
    );

    const profile = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/profile`, {
        headers: restricted.headers,
      }),
    );
    expect(profile.status).toBe(200);

    const methods = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/login-methods`, {
        headers: restricted.headers,
      }),
    );
    expect(methods.status).toBe(200);
    expect(await methods.json()).toMatchObject({
      accessLevel: "restricted",
      linkable: [],
    });

    const clientId = `restricted-rp-${crypto.randomUUID()}`;
    const callback = "https://restricted-rp.example/callback";
    const codeVerifier = "R".repeat(43);
    const codeChallenge = await sha256Base64Url(codeVerifier);
    await insertPublicClient(clientId, callback);
    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callback,
      response_type: "code",
      scope: "openid profile email",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state: "S".repeat(43),
      nonce: "N".repeat(43),
    });
    const authorize = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/authorize?${query}`, {
        headers: restricted.headers,
        redirect: "manual",
      }),
    );
    expect(authorize.status).toBe(302);
    const consentLocation = new URL(
      authorize.headers.get("location") ?? "",
      BASE_URL,
    );
    expect(consentLocation.pathname).toBe("/consent");

    const consentHeaders = new Headers(restricted.headers);
    consentHeaders.set("Sec-Fetch-Mode", "cors");
    const consent = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/consent`, {
        method: "POST",
        headers: consentHeaders,
        body: JSON.stringify({
          accept: true,
          oauth_query: consentLocation.search.slice(1),
        }),
      }),
    );
    expect(consent.status).toBe(200);
    const consentBody = (await consent.json()) as { url?: string };
    const code = new URL(consentBody.url ?? "").searchParams.get("code");
    expect(code).toBeTruthy();

    const token = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/token`, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code ?? "",
          redirect_uri: callback,
          code_verifier: codeVerifier,
          client_id: clientId,
        }),
      }),
    );
    expect(token.status).toBe(200);
    const tokens = (await token.json()) as { access_token?: string };
    const userInfo = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/userinfo`, {
        headers: { Authorization: `Bearer ${tokens.access_token ?? ""}` },
      }),
    );
    expect(userInfo.status).toBe(200);
    expect(await userInfo.json()).toMatchObject({
      sub: restricted.userId,
      "https://pg72.tw/role": "user",
    });
  });

  it("re-reads account state before sensitive actions and audits redacted denials", async () => {
    const developer = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "developer",
    );
    await env.PG72_ID_DB.prepare(
      "UPDATE user SET accessLevel = 'restricted', role = 'user' WHERE id = ?",
    )
      .bind(developer.userId)
      .run();

    const profile = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/profile`, {
        headers: developer.headers,
      }),
    );
    expect(profile.status).toBe(200);

    const clients = await exports.default.fetch(
      new Request(CLIENTS_URL, { headers: developer.headers }),
    );
    expect(clients.status).toBe(403);
    expect(await clients.json()).toEqual({ error: "forbidden" });

    const link = await exports.default.fetch(
      new Request(`${BASE_URL}/link-social`, {
        method: "POST",
        headers: developer.headers,
        body: JSON.stringify({
          callbackURL: `${BASE_URL}/account`,
          provider: "google",
        }),
      }),
    );
    expect(link.status).toBe(403);
    expect(await link.json()).toEqual({ error: "forbidden" });

    const denials = await env.PG72_ID_DB.prepare(
      `SELECT metadata_json
         FROM audit_event
        WHERE event_type = 'account.restricted_action_denied'
          AND subject_id = ?
        ORDER BY occurred_at ASC, id ASC`,
    )
      .bind(developer.userId)
      .all<{ metadata_json: string | null }>();
    expect(
      denials.results.map(({ metadata_json }) => metadata_json),
    ).toEqual([
      '{"surface":"clients.manage"}',
      '{"surface":"provider_link"}',
    ]);
    expect(JSON.stringify(denials.results)).not.toContain("@example.com");
  });
});

describe("restricted account administration", () => {
  it("restricts, revokes, promotes, and preserves explicit role separation", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const target = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "developer",
    );
    const clientId = `restriction-token-${crypto.randomUUID()}`;
    await insertPublicClient(clientId, "https://token.example/callback");
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString();
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthRefreshToken
          (id, token, clientId, sessionId, userId, expiresAt, createdAt, scopes)
         VALUES (?, ?, ?, ?, ?, ?, ?, '["openid"]')`,
      ).bind(
        crypto.randomUUID(),
        crypto.randomUUID(),
        clientId,
        target.sessionId,
        target.userId,
        expiresAt,
        now.toISOString(),
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthAccessToken
          (id, token, clientId, sessionId, userId, expiresAt, createdAt, scopes)
         VALUES (?, ?, ?, ?, ?, ?, ?, '["openid"]')`,
      ).bind(
        crypto.randomUUID(),
        crypto.randomUUID(),
        clientId,
        target.sessionId,
        target.userId,
        expiresAt,
        now.toISOString(),
      ),
    ]);

    const restricted = await setAccess(admin.headers, target.userId, true);
    expect(restricted.status).toBe(200);
    expect(await restricted.json()).toMatchObject({
      accessLevel: "restricted",
      role: "user",
      status: "active",
      userId: target.userId,
    });
    const restrictedState = await env.PG72_ID_DB.prepare(
      `SELECT u.accessLevel, u.role,
              (SELECT COUNT(*) FROM session s WHERE s.userId = u.id) AS sessions,
              (SELECT COUNT(*) FROM oauthAccessToken a WHERE a.userId = u.id)
                AS accessTokens,
              (SELECT COUNT(*) FROM oauthRefreshToken r
                WHERE r.userId = u.id AND r.revoked IS NULL) AS liveRefreshTokens
         FROM user u WHERE u.id = ?`,
    )
      .bind(target.userId)
      .first<{
        accessLevel: string;
        accessTokens: number;
        liveRefreshTokens: number;
        role: string;
        sessions: number;
      }>();
    expect(restrictedState).toEqual({
      accessLevel: "restricted",
      accessTokens: 0,
      liveRefreshTokens: 0,
      role: "user",
      sessions: 0,
    });
    const restrictAudit = await env.PG72_ID_DB.prepare(
      `SELECT actor_user_id, outcome, metadata_json
         FROM audit_event
        WHERE event_type = 'user.access_restricted' AND subject_id = ?
        ORDER BY occurred_at DESC LIMIT 1`,
    )
      .bind(target.userId)
      .first<{
        actor_user_id: string | null;
        metadata_json: string | null;
        outcome: string;
      }>();
    expect(restrictAudit).toMatchObject({
      actor_user_id: admin.userId,
      outcome: "success",
    });
    expect(JSON.parse(restrictAudit?.metadata_json ?? "{}")).toEqual({
      from: "standard",
      previousRole: "developer",
      to: "restricted",
    });

    const replacementSession = await createSessionFor(target.userId);
    expect(
      (
        await exports.default.fetch(
          new Request(`${BASE_URL}/api/account/profile`, {
            headers: replacementSession.headers,
          }),
        )
      ).status,
    ).toBe(200);
    const elevateWhileRestricted = await setRole(
      admin.headers,
      target.userId,
      "developer",
    );
    expect(elevateWhileRestricted.status).toBe(403);
    expect(await elevateWhileRestricted.json()).toEqual({
      error: "restricted_account",
    });

    const promoted = await setAccess(admin.headers, target.userId, false);
    expect(promoted.status).toBe(200);
    expect(await promoted.json()).toMatchObject({
      accessLevel: "standard",
      role: "user",
    });
    expect((await setRole(admin.headers, target.userId, "developer")).status).toBe(
      200,
    );
  });

  it("applies role hierarchy and self-protection to access transitions", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const otherAdmin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const bootstrap = await createBootstrapAdmin();

    const self = await setAccess(admin.headers, admin.userId, true);
    expect(self.status).toBe(409);
    expect(await self.json()).toEqual({ error: "cannot_modify_self" });

    const peer = await setAccess(admin.headers, otherAdmin.userId, true);
    expect(peer.status).toBe(403);
    expect(await peer.json()).toEqual({ error: "role_not_assignable" });

    const byBootstrap = await setAccess(
      bootstrap.headers,
      otherAdmin.userId,
      true,
    );
    expect(byBootstrap.status).toBe(200);
    expect(await byBootstrap.json()).toMatchObject({
      accessLevel: "restricted",
      role: "user",
    });
  });

  it("does not commit a success audit from a stale target snapshot", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const target = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "user",
    );
    const interposed = interposeAfterTargetLoad(async () => {
      await env.PG72_ID_DB.prepare(
        "UPDATE user SET accessLevel = 'restricted', role = 'user' WHERE id = ?",
      )
        .bind(target.userId)
        .run();
    });
    const requestEnv = { ...env, PG72_ID_DB: interposed.database } as Env;
    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${USERS_URL}/${target.userId}/access`, {
        method: "POST",
        headers: admin.headers,
        body: JSON.stringify({ restricted: true }),
      }),
      requestEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(interposed.wasIntercepted()).toBe(true);
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "user_state_changed" });
    const audit = await env.PG72_ID_DB.prepare(
      `SELECT COUNT(*) AS count FROM audit_event
        WHERE event_type = 'user.access_restricted'
          AND subject_id = ? AND outcome = 'success'`,
    )
      .bind(target.userId)
      .first<{ count: number }>();
    expect(audit?.count).toBe(0);
  });
});
