import { env, exports } from "cloudflare:workers";
import { makeSignature } from "better-auth/crypto";
import { describe, expect, it } from "vitest";

import { createAuth } from "../worker/auth";
import { rewriteDormantAccountSignIn } from "../worker/index";
import { createAuthenticatedUser, createSessionFor } from "./helpers";

const BASE_URL = "http://localhost:5173";

interface AccountChoice {
  active: boolean;
  choiceId: string;
  email: string;
  image: string | null;
  name: string;
}

function cookiePairs(headers: Headers): string[] {
  return headers
    .getSetCookie()
    .map((value) => value.split(";", 1)[0] ?? "")
    .filter(Boolean);
}

function requestCookiePairs(headers: Headers): string[] {
  return (headers.get("cookie") ?? "")
    .split(";")
    .map((value) => value.trim())
    .filter(Boolean);
}

function withCookies(source: Headers, cookies: string[]): Headers {
  const headers = new Headers(source);
  headers.set("Cookie", cookies.join("; "));
  return headers;
}

function withResponseCookies(source: Headers, response: Headers): Headers {
  const jar = new Map(
    requestCookiePairs(source).map((cookie) => {
      const separator = cookie.indexOf("=");
      return [cookie.slice(0, separator), cookie] as const;
    }),
  );
  for (const cookie of cookiePairs(response)) {
    const separator = cookie.indexOf("=");
    const name = cookie.slice(0, separator);
    if (cookie.slice(separator + 1).length === 0) jar.delete(name);
    else jar.set(name, cookie);
  }
  return withCookies(source, [...jar.values()]);
}

function multiCookies(headers: Headers): string[] {
  return cookiePairs(headers).filter((cookie) => cookie.includes("_multi-"));
}

function canonicalProviderQuery(params: URLSearchParams): string {
  return new URLSearchParams(
    [...params.entries()].sort(([keyA, valueA], [keyB, valueB]) => {
      if (keyA < keyB) return -1;
      if (keyA > keyB) return 1;
      if (valueA < valueB) return -1;
      if (valueA > valueB) return 1;
      return 0;
    }),
  ).toString();
}

async function resignProviderQuery(
  params: URLSearchParams,
): Promise<URLSearchParams> {
  const signed = new URLSearchParams(params);
  signed.delete("sig");
  signed.set(
    "sig",
    await makeSignature(
      canonicalProviderQuery(signed),
      env.BETTER_AUTH_SECRET,
    ),
  );
  return signed;
}

async function signedProviderQuery(): Promise<string> {
  const params = new URLSearchParams({
    ba_iat: String(Date.now()),
    client_id: "test",
    exp: String(Math.floor(Date.now() / 1_000) + 600),
    redirect_uri: "https://rp.example/callback",
    response_type: "code",
    scope: "openid email",
  });
  const markerNames = [...new Set([...params.keys(), "ba_param"])].sort();
  for (const name of markerNames) params.append("ba_param", name);
  return (await resignProviderQuery(params)).toString();
}

async function signedSessionCookie(token: string): Promise<string> {
  return `${token}.${await makeSignature(token, env.BETTER_AUTH_SECRET)}`;
}

async function listAccounts(headers: Headers): Promise<{
  accounts: AccountChoice[];
  response: Response;
}> {
  const response = await exports.default.fetch(
    new Request(`${BASE_URL}/api/account-chooser`, { headers }),
  );
  const payload = (await response.json()) as { accounts?: AccountChoice[] };
  return { accounts: payload.accounts ?? [], response };
}

async function rememberTwoAccounts() {
  const firstEmail = `${crypto.randomUUID()}@example.com`;
  const secondEmail = `${crypto.randomUUID()}@example.com`;
  const first = await createAuthenticatedUser(firstEmail);
  const firstList = await listAccounts(first.headers);
  expect(firstList.response.status).toBe(200);
  const firstRemembered = multiCookies(firstList.response.headers);
  expect(firstRemembered).toHaveLength(1);

  const second = await createAuthenticatedUser(secondEmail);
  const secondPrimary = requestCookiePairs(second.headers).filter(
    (cookie) => !cookie.includes("_multi-"),
  );
  const secondBeforeAdoption = withCookies(second.headers, [
    ...secondPrimary,
    ...firstRemembered,
  ]);
  const secondList = await listAccounts(secondBeforeAdoption);
  expect(secondList.response.status).toBe(200);
  const secondRemembered = multiCookies(secondList.response.headers);
  expect(secondRemembered).toHaveLength(1);

  const browserHeaders = withCookies(second.headers, [
    ...secondPrimary,
    ...firstRemembered,
    ...secondRemembered,
  ]);
  return {
    browserHeaders,
    first,
    firstEmail,
    firstRemembered,
    second,
    secondEmail,
    secondRemembered,
  };
}

async function insertClient(clientId: string, redirectUri: string): Promise<void> {
  const now = new Date().toISOString();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO oauthClient (
      id, clientId, disabled, skipConsent, scopes, createdAt, updatedAt, name,
      redirectUris, tokenEndpointAuthMethod, grantTypes, responseTypes,
      public, requirePKCE
    ) VALUES (?, ?, 0, 0, ?, ?, ?, ?, ?, 'none', ?, '["code"]', 1, 1)`,
  )
    .bind(
      crypto.randomUUID(),
      clientId,
      '["openid","profile","email"]',
      now,
      now,
      "Account Chooser Test",
      JSON.stringify([redirectUri]),
      '["authorization_code"]',
    )
    .run();
}

async function insertTokenFamily(
  clientId: string,
  session: { sessionId: string; userId: string },
  label: string,
): Promise<{ accessToken: string; refreshToken: string }> {
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 60 * 60 * 1_000).toISOString();
  const refreshId = crypto.randomUUID();
  const refreshToken = `pg72_rt_${label}_${crypto.randomUUID()}`;
  const accessToken = `pg72_at_${label}_${crypto.randomUUID()}`;
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `INSERT INTO oauthRefreshToken
        (id, token, clientId, sessionId, userId, expiresAt, createdAt, scopes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      refreshId,
      refreshToken,
      clientId,
      session.sessionId,
      session.userId,
      expiresAt,
      now,
      '["openid"]',
    ),
    env.PG72_ID_DB.prepare(
      `INSERT INTO oauthAccessToken
        (id, token, clientId, sessionId, userId, refreshId, expiresAt, createdAt, scopes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      crypto.randomUUID(),
      accessToken,
      clientId,
      session.sessionId,
      session.userId,
      refreshId,
      expiresAt,
      now,
      '["openid"]',
    ),
  ]);
  return { accessToken, refreshToken };
}

function authorizeURL(
  clientId: string,
  redirectUri: string,
  prompt?: string,
): string {
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
  if (prompt) query.set("prompt", prompt);
  return `${BASE_URL}/oauth2/authorize?${query}`;
}

async function authorize(
  clientId: string,
  redirectUri: string,
  headers: Headers,
  prompt?: string,
): Promise<Response> {
  return exports.default.fetch(
    new Request(authorizeURL(clientId, redirectUri, prompt), {
      headers,
      redirect: "manual",
    }),
  );
}

describe("PGID account chooser", () => {
  it("adopts the current session and exposes only bounded opaque choices", async () => {
    const remembered = await rememberTwoAccounts();
    const listed = await listAccounts(remembered.browserHeaders);

    expect(listed.accounts).toHaveLength(2);
    expect(listed.accounts.map((account) => account.email)).toEqual([
      remembered.secondEmail,
      remembered.firstEmail,
    ]);
    expect(listed.accounts.filter((account) => account.active)).toHaveLength(1);
    expect(listed.accounts[0]?.active).toBe(true);
    expect(listed.accounts.every((account) => /^[A-Za-z0-9_-]+$/.test(account.choiceId))).toBe(true);
    const serialized = JSON.stringify(listed.accounts);
    expect(serialized).not.toContain(remembered.first.token);
    expect(serialized).not.toContain(remembered.second.token);
    expect(serialized).not.toContain(remembered.first.userId);
    expect(serialized).not.toContain(remembered.second.userId);

    const raw = await exports.default.fetch(
      `${BASE_URL}/multi-session/list-device-sessions`,
    );
    expect(raw.status).toBe(404);

    const rawSetActive = await exports.default.fetch(
      new Request(`${BASE_URL}/multi-session/set-active`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionToken: "not-exposed" }),
      }),
    );
    expect(rawSetActive.status).toBe(404);
    expect(rawSetActive.headers.getSetCookie()).toHaveLength(0);

    const rawTelegramCompletion = await exports.default.fetch(
      new Request(`${BASE_URL}/complete-telegram-account-sign-in`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId: remembered.first.userId }),
      }),
    );
    expect(rawTelegramCompletion.status).toBe(404);
    expect(rawTelegramCompletion.headers.getSetCookie()).toHaveLength(0);
  });

  it("expires duplicate and stale choices while preserving all five usable slots", async () => {
    const originalEmail = `${crypto.randomUUID()}@example.com`;
    const original = await createAuthenticatedUser(originalEmail);
    const originalList = await listAccounts(original.headers);
    const originalRemembered = multiCookies(originalList.response.headers);
    expect(originalRemembered).toHaveLength(1);

    const unrelated: Array<{
      email: string;
      remembered: string;
      sessionId: string;
      token: string;
    }> = [];
    for (let index = 0; index < 4; index += 1) {
      const email = `${crypto.randomUUID()}@example.com`;
      const account = await createAuthenticatedUser(email);
      const listed = await listAccounts(account.headers);
      const remembered = multiCookies(listed.response.headers);
      expect(remembered).toHaveLength(1);
      unrelated.push({
        email,
        remembered: remembered[0] ?? "",
        sessionId: account.sessionId,
        token: account.token,
      });
    }

    const current = await createSessionFor(original.userId);
    const currentPrimary = requestCookiePairs(current.headers).filter(
      (cookie) => !cookie.includes("_multi-"),
    );
    const staleToken = crypto.randomUUID();
    const staleCookie =
      `pg72_id.session_token_multi-${staleToken.toLowerCase()}=` +
      await signedSessionCookie(staleToken);
    const browserHeaders = withCookies(current.headers, [
      ...currentPrimary,
      ...originalRemembered,
      ...unrelated.map((account) => account.remembered),
      staleCookie,
    ]);
    const adopted = await listAccounts(browserHeaders);

    expect(adopted.response.status).toBe(200);
    expect(adopted.accounts).toHaveLength(5);
    expect(adopted.accounts[0]?.email).toBe(originalEmail);
    expect(new Set(adopted.accounts.map((account) => account.email))).toEqual(
      new Set([originalEmail, ...unrelated.map((account) => account.email)]),
    );
    expect(adopted.accounts.filter((account) => account.active)).toEqual([
      expect.objectContaining({ active: true, email: originalEmail }),
    ]);
    const setCookies = adopted.response.headers.getSetCookie();
    expect(setCookies.some((cookie) =>
      cookie.includes(`_multi-${original.token.toLowerCase()}=`) &&
      /Max-Age=0/i.test(cookie),
    )).toBe(true);
    expect(setCookies.some((cookie) =>
      cookie.includes(`_multi-${staleToken.toLowerCase()}=`) &&
      /Max-Age=0/i.test(cookie),
    )).toBe(true);
    expect(setCookies.some((cookie) =>
      cookie.includes(`_multi-${current.token.toLowerCase()}=`) &&
      !/Max-Age=0/i.test(cookie),
    )).toBe(true);
    for (const account of unrelated) {
      expect(setCookies.some((cookie) =>
        cookie.includes(`_multi-${account.token.toLowerCase()}=`) &&
        /Max-Age=0/i.test(cookie),
      )).toBe(false);
    }
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM session WHERE id = ?")
        .bind(original.sessionId)
        .first(),
    ).toBeNull();
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM session WHERE id = ?")
        .bind(current.sessionId)
        .first(),
    ).not.toBeNull();
    for (const account of unrelated) {
      expect(
        await env.PG72_ID_DB.prepare("SELECT id FROM session WHERE id = ?")
          .bind(account.sessionId)
          .first(),
      ).not.toBeNull();
    }
  });

  it("removes five corrupt canonical choices before applying the session cap", async () => {
    const currentEmail = `${crypto.randomUUID()}@example.com`;
    const current = await createAuthenticatedUser(currentEmail);
    const corruptTokens = Array.from({ length: 5 }, () => crypto.randomUUID());
    const browserHeaders = withCookies(current.headers, [
      ...requestCookiePairs(current.headers),
      ...corruptTokens.map(
        (token) =>
          `pg72_id.session_token_multi-${token.toLowerCase()}=${token}.invalid`,
      ),
    ]);

    const adopted = await listAccounts(browserHeaders);
    expect(adopted.accounts).toEqual([
      expect.objectContaining({ active: true, email: currentEmail }),
    ]);
    const setCookies = adopted.response.headers.getSetCookie();
    expect(setCookies.some((cookie) =>
      cookie.includes(`_multi-${current.token.toLowerCase()}=`) &&
      !/Max-Age=0/i.test(cookie),
    )).toBe(true);
    for (const token of corruptTokens) {
      expect(setCookies.some((cookie) =>
        cookie.includes(`_multi-${token.toLowerCase()}=`) &&
        /Max-Age=0/i.test(cookie),
      )).toBe(true);
    }
  });

  it("projects standard-base64 HMAC output to an accepted base64url choice", async () => {
    const email = `${crypto.randomUUID()}@example.com`;
    const current = await createAuthenticatedUser(email);
    let token = "";
    let rawChoice = "";
    for (let attempt = 0; attempt < 128; attempt += 1) {
      const candidate = crypto.randomUUID();
      const signature = await makeSignature(
        `pgid-account-choice:v1:${candidate}`,
        env.BETTER_AUTH_SECRET,
      );
      if (signature.includes("+") && signature.includes("/")) {
        token = candidate;
        rawChoice = signature;
        break;
      }
    }
    expect(token).not.toBe("");
    expect(rawChoice).toContain("+");
    expect(rawChoice).toContain("/");
    expect(rawChoice).toContain("=");
    await env.PG72_ID_DB.prepare("UPDATE session SET token = ? WHERE id = ?")
      .bind(token, current.sessionId)
      .run();
    const signedToken = await signedSessionCookie(token);
    const primaryHeaders = withCookies(current.headers, [
      `pg72_id.session_token=${signedToken}`,
      `__Secure-pg72_id.session_token=${signedToken}`,
    ]);

    const listed = await listAccounts(primaryHeaders);
    expect(listed.accounts).toHaveLength(1);
    const choice = listed.accounts[0];
    expect(choice?.choiceId).toBe(
      rawChoice.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, ""),
    );
    expect(choice?.choiceId).toMatch(/^[A-Za-z0-9_-]+$/);

    const browserHeaders = withResponseCookies(
      primaryHeaders,
      listed.response.headers,
    );
    const clientId = `chooser-base64url-${crypto.randomUUID()}`;
    const redirectUri = "https://chooser-base64url.example/callback";
    await insertClient(clientId, redirectUri);
    const start = await authorize(clientId, redirectUri, browserHeaders);
    const chooserLocation = new URL(
      start.headers.get("location") ?? "",
      BASE_URL,
    );
    expect(chooserLocation.pathname).toBe("/select-account");
    const headers = new Headers(browserHeaders);
    headers.set("Content-Type", "application/json");
    expect(headers.has("sec-fetch-mode")).toBe(false);
    const selected = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account-chooser/select`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          choiceId: choice?.choiceId,
          oauth_query: chooserLocation.search.slice(1),
        }),
      }),
    );
    expect(selected.status).toBe(200);
    expect(await selected.json()).toEqual(
      expect.objectContaining({ redirect: true }),
    );
  });

  it("handles account-selection prompts without bypassing prompt semantics", async () => {
    const clientId = `chooser-prompts-${crypto.randomUUID()}`;
    const redirectUri = "https://chooser-prompts.example/callback";
    await insertClient(clientId, redirectUri);
    const remembered = await rememberTwoAccounts();

    const ordinary = await authorize(
      clientId,
      redirectUri,
      remembered.browserHeaders,
    );
    expect(new URL(ordinary.headers.get("location") ?? "", BASE_URL).pathname).toBe(
      "/select-account",
    );

    const forceLogin = await authorize(
      clientId,
      redirectUri,
      remembered.browserHeaders,
      "login",
    );
    expect(new URL(forceLogin.headers.get("location") ?? "", BASE_URL).pathname).toBe(
      "/sign-in",
    );

    const silent = await authorize(
      clientId,
      redirectUri,
      remembered.browserHeaders,
      "none",
    );
    const silentTarget = new URL(silent.headers.get("location") ?? "");
    expect(`${silentTarget.origin}${silentTarget.pathname}`).toBe(redirectUri);
    expect(silentTarget.searchParams.get("error")).toBe(
      "account_selection_required",
    );

    const dormantHeaders = withCookies(remembered.browserHeaders, [
      ...remembered.firstRemembered,
      ...remembered.secondRemembered,
    ]);
    const dormantSilent = await authorize(
      clientId,
      redirectUri,
      dormantHeaders,
      "none",
    );
    const dormantTarget = new URL(
      dormantSilent.headers.get("location") ?? "",
    );
    expect(`${dormantTarget.origin}${dormantTarget.pathname}`).toBe(redirectUri);
    expect(dormantTarget.searchParams.get("error")).toBe(
      "account_selection_required",
    );
    expect(dormantTarget.searchParams.get("state")).toBe("B".repeat(43));
    expect(dormantTarget.searchParams.get("iss")).toBe(BASE_URL);
    expect(dormantTarget.searchParams.has("code")).toBe(false);
    expect(dormantTarget.pathname).not.toBe("/select-account");

    const emptySilent = await authorize(
      clientId,
      redirectUri,
      new Headers(),
      "none",
    );
    expect(
      new URL(emptySilent.headers.get("location") ?? "").searchParams.get(
        "error",
      ),
    ).toBe("login_required");

    await env.PG72_ID_DB.prepare(
      "UPDATE session SET expiresAt = ? WHERE token = ?",
    )
      .bind(new Date(0).toISOString(), remembered.first.token)
      .run();
    const staleHeaders = withCookies(remembered.browserHeaders, [
      ...remembered.firstRemembered,
    ]);
    const staleSilent = await authorize(
      clientId,
      redirectUri,
      staleHeaders,
      "none",
    );
    expect(
      new URL(staleSilent.headers.get("location") ?? "").searchParams.get(
        "error",
      ),
    ).toBe("login_required");
  });

  it("rewrites both JSON and Location sign-in responses for dormant cookies", async () => {
    const remembered = await rememberTwoAccounts();
    const dormantHeaders = withCookies(remembered.browserHeaders, [
      ...remembered.firstRemembered,
      ...remembered.secondRemembered,
    ]);
    const request = new Request(`${BASE_URL}/oauth2/authorize`, {
      headers: dormantHeaders,
    });
    const auth = createAuth(env);
    const signedQuery = await signedProviderQuery();

    const jsonResponse = await rewriteDormantAccountSignIn(
      auth,
      request,
      Response.json(
        {
          redirect: true,
          url: `${BASE_URL}/sign-in?${signedQuery}`,
        },
        { headers: { "X-Test-Preserve": "json" } },
      ),
      env.BETTER_AUTH_SECRET,
    );
    expect((await jsonResponse.json()) as { url: string }).toMatchObject({
      url: `${BASE_URL}/select-account?${signedQuery}`,
    });
    expect(jsonResponse.headers.get("x-test-preserve")).toBe("json");

    const locationResponse = await rewriteDormantAccountSignIn(
      auth,
      request,
      new Response(null, {
        status: 302,
        headers: {
          Location: `${BASE_URL}/sign-in?${signedQuery}`,
          "X-Test-Preserve": "location",
        },
      }),
      env.BETTER_AUTH_SECRET,
    );
    expect(locationResponse.status).toBe(302);
    expect(locationResponse.headers.get("location")).toBe(
      `${BASE_URL}/select-account?${signedQuery}`,
    );
    expect(locationResponse.headers.get("x-test-preserve")).toBe("location");

    const tampered = new URLSearchParams(signedQuery);
    tampered.set("sig", "tampered");
    const missingMarker = new URLSearchParams(signedQuery);
    const markerNames = missingMarker
      .getAll("ba_param")
      .filter((name) => name !== "client_id");
    missingMarker.delete("ba_param");
    for (const name of markerNames) missingMarker.append("ba_param", name);
    const resignedMissingMarker = await resignProviderQuery(missingMarker);
    const expired = new URLSearchParams(signedQuery);
    expired.set("exp", String(Math.floor(Date.now() / 1_000) - 1));
    const resignedExpired = await resignProviderQuery(expired);
    for (const invalidQuery of [tampered, resignedMissingMarker, resignedExpired]) {
      const url = `${BASE_URL}/sign-in?${invalidQuery}`;
      const invalidResponse = await rewriteDormantAccountSignIn(
        auth,
        request,
        Response.json({ redirect: true, url }),
        env.BETTER_AUTH_SECRET,
      );
      expect(await invalidResponse.json()).toEqual({ redirect: true, url });
    }

    const sameOriginRpCallback = Response.json({
      redirect: true,
      url: `${BASE_URL}/sign-in?sig=rp&state=unchanged`,
    });
    const sameOriginUntouched = await rewriteDormantAccountSignIn(
      auth,
      request,
      sameOriginRpCallback,
      env.BETTER_AUTH_SECRET,
    );
    expect(await sameOriginUntouched.json()).toEqual({
      redirect: true,
      url: `${BASE_URL}/sign-in?sig=rp&state=unchanged`,
    });

    const rpCallback = Response.json({
      redirect: true,
      url: `https://rp.example/sign-in?sig=rp&state=unchanged`,
    });
    const untouched = await rewriteDormantAccountSignIn(
      auth,
      request,
      rpCallback,
      env.BETTER_AUTH_SECRET,
    );
    expect(await untouched.json()).toEqual({
      redirect: true,
      url: "https://rp.example/sign-in?sig=rp&state=unchanged",
    });
  });

  it("switches another remembered account and continues authorization once", async () => {
    const clientId = `chooser-switch-${crypto.randomUUID()}`;
    const redirectUri = "https://chooser-switch.example/callback";
    await insertClient(clientId, redirectUri);
    const remembered = await rememberTwoAccounts();
    const listed = await listAccounts(remembered.browserHeaders);
    const firstChoice = listed.accounts.find(
      (account) => account.email === remembered.firstEmail,
    );
    expect(firstChoice?.active).toBe(false);

    const start = await authorize(
      clientId,
      redirectUri,
      remembered.browserHeaders,
    );
    const chooserLocation = new URL(
      start.headers.get("location") ?? "",
      BASE_URL,
    );
    expect(chooserLocation.pathname).toBe("/select-account");
    const signedOAuthQuery = chooserLocation.search.slice(1);
    const headers = new Headers(remembered.browserHeaders);
    headers.set("Content-Type", "application/json");
    expect(headers.has("sec-fetch-mode")).toBe(false);
    const invalid = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account-chooser/select`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          choiceId: firstChoice?.choiceId,
          oauth_query: signedOAuthQuery.replace(/sig=[^&]+/, "sig=invalid"),
        }),
      }),
    );
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toEqual({
      error: "invalid_authorization_request",
    });
    expect(invalid.headers.getSetCookie()).toHaveLength(0);

    const switched = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account-chooser/select`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          choiceId: firstChoice?.choiceId,
          oauth_query: signedOAuthQuery,
        }),
      }),
    );

    const continuation = (await switched.json()) as {
      error?: string;
      redirect?: boolean;
      url?: string;
    };
    expect(switched.status, JSON.stringify(continuation)).toBe(200);
    expect(continuation.redirect).toBe(true);
    expect(new URL(continuation.url ?? "").pathname).toBe("/consent");
    const serialized = JSON.stringify(continuation);
    expect(serialized).not.toContain(remembered.first.token);
    expect(serialized).not.toContain(remembered.second.token);
    expect(serialized).not.toContain(remembered.first.userId);
    expect(serialized).not.toContain(remembered.second.userId);
    expect(continuation).not.toHaveProperty("session");
    expect(switched.headers.getSetCookie().some((cookie) =>
      cookie.startsWith("pg72_id.session_token="),
    )).toBe(true);
    expect(switched.headers.getSetCookie().some((cookie) =>
      cookie.includes(`_multi-${remembered.first.token.toLowerCase()}=`) &&
      /Max-Age=0/i.test(cookie),
    )).toBe(false);
    const selectedSession = await env.PG72_ID_DB.prepare(
      "SELECT id FROM session WHERE token = ?",
    )
      .bind(remembered.first.token)
      .first();
    expect(selectedSession).not.toBeNull();
  });

  it("returns a distinct cookie-free conflict when a listed choice expires", async () => {
    const clientId = `chooser-stale-${crypto.randomUUID()}`;
    const redirectUri = "https://chooser-stale.example/callback";
    await insertClient(clientId, redirectUri);
    const remembered = await rememberTwoAccounts();
    const listed = await listAccounts(remembered.browserHeaders);
    const staleChoice = listed.accounts.find(
      (account) => account.email === remembered.firstEmail,
    );
    expect(staleChoice?.active).toBe(false);
    const start = await authorize(
      clientId,
      redirectUri,
      remembered.browserHeaders,
    );
    const chooserLocation = new URL(
      start.headers.get("location") ?? "",
      BASE_URL,
    );
    await env.PG72_ID_DB.prepare("DELETE FROM session WHERE id = ?")
      .bind(remembered.first.sessionId)
      .run();

    const headers = new Headers(remembered.browserHeaders);
    headers.set("Content-Type", "application/json");
    expect(headers.has("sec-fetch-mode")).toBe(false);
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account-chooser/select`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          choiceId: staleChoice?.choiceId,
          oauth_query: chooserLocation.search.slice(1),
        }),
      }),
    );

    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "account_choice_expired" });
    expect(response.headers.getSetCookie()).toHaveLength(0);
  });

  it("signs out only the active account and preserves dormant sessions", async () => {
    const remembered = await rememberTwoAccounts();
    const clientId = `chooser-signout-${crypto.randomUUID()}`;
    await insertClient(clientId, "https://chooser-signout.example/callback");
    const firstTokens = await insertTokenFamily(
      clientId,
      remembered.first,
      "dormant",
    );
    const secondTokens = await insertTokenFamily(
      clientId,
      remembered.second,
      "current",
    );
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/sign-out`, {
        method: "POST",
        headers: remembered.browserHeaders,
      }),
    );

    expect(response.status).toBe(200);
    const expired = response.headers
      .getSetCookie()
      .filter((cookie) => /Max-Age=0/i.test(cookie));
    expect(expired.some((cookie) =>
      cookie.startsWith("pg72_id.session_token="),
    )).toBe(true);
    expect(expired.some((cookie) =>
      cookie.includes(`_multi-${remembered.second.token.toLowerCase()}=`),
    )).toBe(true);
    expect(expired.some((cookie) =>
      cookie.includes(`_multi-${remembered.first.token.toLowerCase()}=`),
    )).toBe(false);

    const firstSession = await env.PG72_ID_DB.prepare(
      "SELECT id FROM session WHERE token = ?",
    )
      .bind(remembered.first.token)
      .first();
    const secondSession = await env.PG72_ID_DB.prepare(
      "SELECT id FROM session WHERE token = ?",
    )
      .bind(remembered.second.token)
      .first();
    expect(firstSession).not.toBeNull();
    expect(secondSession).toBeNull();

    const refreshRows = await env.PG72_ID_DB.prepare(
      `SELECT token, sessionId, revoked
         FROM oauthRefreshToken
        WHERE token IN (?, ?)
        ORDER BY token`,
    )
      .bind(firstTokens.refreshToken, secondTokens.refreshToken)
      .all<{ revoked: string | null; sessionId: string | null; token: string }>();
    const dormantRefresh = refreshRows.results.find(
      (row) => row.token === firstTokens.refreshToken,
    );
    const currentRefresh = refreshRows.results.find(
      (row) => row.token === secondTokens.refreshToken,
    );
    expect(dormantRefresh).toMatchObject({
      revoked: null,
      sessionId: remembered.first.sessionId,
    });
    expect(currentRefresh?.revoked).not.toBeNull();
    expect(currentRefresh?.sessionId).toBeNull();

    const accessRows = await env.PG72_ID_DB.prepare(
      "SELECT token FROM oauthAccessToken WHERE token IN (?, ?) ORDER BY token",
    )
      .bind(firstTokens.accessToken, secondTokens.accessToken)
      .all<{ token: string }>();
    expect(accessRows.results.map((row) => row.token)).toEqual([
      firstTokens.accessToken,
    ]);

    const audit = await env.PG72_ID_DB.prepare(
      `SELECT event_type, metadata_json
         FROM audit_event
        WHERE event_type = 'session.revoked' AND subject_id = ?`,
    )
      .bind(remembered.second.userId)
      .all<{ event_type: string; metadata_json: string | null }>();
    expect(audit.results).toHaveLength(1);
    expect(audit.results[0]).toEqual({
      event_type: "session.revoked",
      metadata_json: '{"reason":"sign_out"}',
    });

    const deliveries = await env.PG72_ID_DB.prepare(
      `SELECT reason, session_id
         FROM logout_delivery
        WHERE session_id IN (?, ?)
        ORDER BY session_id`,
    )
      .bind(remembered.first.sessionId, remembered.second.sessionId)
      .all<{ reason: string; session_id: string }>();
    expect(deliveries.results).toEqual([
      { reason: "sign_out", session_id: remembered.second.sessionId },
    ]);
  });

  it("signs out a legacy primary without removing an unrelated remembered peer", async () => {
    const peer = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const peerList = await listAccounts(peer.headers);
    const peerRemembered = multiCookies(peerList.response.headers);
    expect(peerRemembered).toHaveLength(1);
    const legacy = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const legacyPrimary = requestCookiePairs(legacy.headers).filter(
      (cookie) => !cookie.includes("_multi-"),
    );
    const browserHeaders = withCookies(legacy.headers, [
      ...legacyPrimary,
      ...peerRemembered,
    ]);

    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/sign-out`, {
        method: "POST",
        headers: browserHeaders,
      }),
    );

    expect(response.status).toBe(200);
    const expired = response.headers
      .getSetCookie()
      .filter((cookie) => /Max-Age=0/i.test(cookie));
    expect(expired.some((cookie) =>
      cookie.startsWith("pg72_id.session_token="),
    )).toBe(true);
    expect(expired.some((cookie) =>
      cookie.includes(`_multi-${peer.token.toLowerCase()}=`),
    )).toBe(false);
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM session WHERE id = ?")
        .bind(legacy.sessionId)
        .first(),
    ).toBeNull();
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM session WHERE id = ?")
        .bind(peer.sessionId)
        .first(),
    ).not.toBeNull();
  });

  it("keeps legacy and remembered-only sign-out behavior bounded", async () => {
    const legacy = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const legacyResponse = await exports.default.fetch(
      new Request(`${BASE_URL}/sign-out`, {
        method: "POST",
        headers: legacy.headers,
      }),
    );
    expect(legacyResponse.status).toBe(200);
    expect(legacyResponse.headers.getSetCookie().some((cookie) =>
      cookie.startsWith("pg72_id.session_token=") && /Max-Age=0/i.test(cookie),
    )).toBe(true);
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM session WHERE id = ?")
        .bind(legacy.sessionId)
        .first(),
    ).toBeNull();

    const remembered = await rememberTwoAccounts();
    const rememberedOnly = withCookies(remembered.browserHeaders, [
      ...remembered.firstRemembered,
      ...remembered.secondRemembered,
    ]);
    const auditBefore = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM audit_event WHERE subject_id IN (?, ?)",
    )
      .bind(remembered.first.userId, remembered.second.userId)
      .first<{ count: number }>();
    const noPrimaryResponse = await exports.default.fetch(
      new Request(`${BASE_URL}/sign-out`, {
        method: "POST",
        headers: rememberedOnly,
      }),
    );
    expect(noPrimaryResponse.status).toBe(200);
    expect(noPrimaryResponse.headers.getSetCookie().some((cookie) =>
      cookie.includes("_multi-") && /Max-Age=0/i.test(cookie),
    )).toBe(false);
    const surviving = await env.PG72_ID_DB.prepare(
      "SELECT id FROM session WHERE id IN (?, ?) ORDER BY id",
    )
      .bind(remembered.first.sessionId, remembered.second.sessionId)
      .all<{ id: string }>();
    expect(surviving.results).toHaveLength(2);
    const auditAfter = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM audit_event WHERE subject_id IN (?, ?)",
    )
      .bind(remembered.first.userId, remembered.second.userId)
      .first<{ count: number }>();
    expect(auditAfter?.count).toBe(auditBefore?.count);
  });
});
