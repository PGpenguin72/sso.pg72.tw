import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";

import { requireCentralSessionId } from "../worker/oidc-claims";

const discovery = {
  issuer: "http://localhost:5173",
  authorization_endpoint: "http://localhost:5173/oauth2/authorize",
  token_endpoint: "http://localhost:5173/oauth2/token",
  userinfo_endpoint: "http://localhost:5173/oauth2/userinfo",
  jwks_uri: "http://localhost:5173/.well-known/jwks.json",
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["EdDSA"],
  code_challenge_methods_supported: ["S256"],
};

interface SigningFixture {
  privateKey: CryptoKey;
  publicJwk: JsonWebKey & { alg: string; kid: string; use: string };
}

interface OidcLogin {
  authorizationUrl: URL;
  cookie: string;
  nonce: string;
  state: string;
  transactionId: string;
}

interface SignedOidcServerOptions {
  audience: string;
  centralSessionId: string;
  subject: string;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function base64Url(value: string | ArrayBuffer): string {
  const bytes =
    typeof value === "string"
      ? new TextEncoder().encode(value)
      : new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

async function createSigningFixture(): Promise<SigningFixture> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return {
    privateKey: keyPair.privateKey,
    publicJwk: {
      ...publicJwk,
      alg: "EdDSA",
      kid: "test-signing-key",
      use: "sig",
    },
  };
}

async function signIdToken(
  privateKey: CryptoKey,
  claims: Record<string, unknown>,
): Promise<string> {
  const header = base64Url(
    JSON.stringify({ alg: "EdDSA", kid: "test-signing-key", typ: "JWT" }),
  );
  const payload = base64Url(JSON.stringify(claims));
  const input = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    { name: "Ed25519" },
    privateKey,
    new TextEncoder().encode(input),
  );
  return `${input}.${base64Url(signature)}`;
}

async function beginOidcLogin(
  url = "http://localhost:5174/login",
): Promise<OidcLogin> {
  const response = await exports.default.fetch(
    new Request(url, { redirect: "manual" }),
  );
  expect(response.status).toBe(302);

  const authorizationUrl = new URL(response.headers.get("location") ?? "");
  const cookie = response.headers.get("set-cookie")?.split(";", 1)[0];
  const nonce = authorizationUrl.searchParams.get("nonce");
  const state = authorizationUrl.searchParams.get("state");
  if (!cookie || !nonce || !state) {
    throw new Error("OIDC login did not create a complete transaction");
  }
  const transactionId = cookie.split("=", 2)[1];
  if (!transactionId) throw new Error("OIDC transaction cookie was empty");

  return { authorizationUrl, cookie, nonce, state, transactionId };
}

function callbackUrl(parameters: Record<string, string>): string {
  const url = new URL("http://localhost:5174/callback");
  for (const [name, value] of Object.entries(parameters)) {
    url.searchParams.set(name, value);
  }
  return url.href;
}

function stubSignedOidcServer(
  signing: SigningFixture,
  options: SignedOidcServerOptions,
) {
  const requests = { jwks: 0, token: 0, userInfo: 0 };
  let expectedNonce: string | undefined;

  const outbound = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request =
      input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    if (url.pathname === "/.well-known/openid-configuration") {
      return json(discovery);
    }
    if (url.pathname === "/oauth2/token") {
      requests.token += 1;
      const parameters = await request.formData();
      expect(parameters.get("client_id")).toBe("pg72-test-rp");
      expect(parameters.has("resource")).toBe(false);
      if (!expectedNonce) throw new Error("Expected nonce was not configured");

      const now = Math.floor(Date.now() / 1000);
      return json({
        access_token: "test-access-token",
        expires_in: 900,
        id_token: await signIdToken(signing.privateKey, {
          aud: options.audience,
          exp: now + 600,
          iat: now,
          iss: discovery.issuer,
          nonce: expectedNonce,
          sid: options.centralSessionId,
          sub: options.subject,
        }),
        token_type: "Bearer",
      });
    }
    if (url.pathname === "/.well-known/jwks.json") {
      requests.jwks += 1;
      return json({ keys: [signing.publicJwk] });
    }
    if (url.pathname === "/oauth2/userinfo") {
      requests.userInfo += 1;
      expect(request.headers.get("authorization")).toBe(
        "Bearer test-access-token",
      );
      return json({
        email: "protocol-test@example.com",
        name: "Protocol Test",
        sub: options.subject,
      });
    }
    return new Response(null, { status: 404 });
  });
  vi.stubGlobal("fetch", outbound);

  return {
    requests,
    setExpectedNonce(nonce: string) {
      expectedNonce = nonce;
    },
  };
}

async function rpSessionCount(subject?: string): Promise<number> {
  const row = subject
    ? await env.TEST_RP_DB.prepare(
        "SELECT COUNT(*) AS count FROM rp_session WHERE subject = ?",
      )
        .bind(subject)
        .first<{ count: number }>()
    : await env.TEST_RP_DB.prepare(
        "SELECT COUNT(*) AS count FROM rp_session",
      ).first<{ count: number }>();
  if (!row) throw new Error("RP session count was not returned");
  return row.count;
}

async function sessionTokenHash(token: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token),
  );
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

async function seedRpSession(centralSessionId: string): Promise<string> {
  const token = crypto.randomUUID();
  const now = new Date();
  await env.TEST_RP_DB.prepare(
    `INSERT INTO rp_session
      (id, token_hash, subject, central_session_id, display_name, email,
       expires_at, created_at, last_seen_at)
     VALUES (?, ?, ?, ?, NULL, NULL, ?, ?, ?)`,
  )
    .bind(
      crypto.randomUUID(),
      await sessionTokenHash(token),
      crypto.randomUUID(),
      centralSessionId,
      new Date(now.getTime() + 60 * 60 * 1000).toISOString(),
      now.toISOString(),
      now.toISOString(),
    )
    .run();
  return token;
}

function logoutClaims(
  sid: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    aud: "pg72-test-rp",
    events: {
      "http://schemas.openid.net/event/backchannel-logout": {},
    },
    exp: now + 120,
    iat: now,
    iss: discovery.issuer,
    jti: crypto.randomUUID(),
    sid,
    ...overrides,
  };
}

async function postLogoutToken(token: string): Promise<Response> {
  return exports.default.fetch(
    new Request("http://localhost:5174/backchannel-logout", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ logout_token: token }),
    }),
  );
}

function stubLogoutJwksResponse(response: () => Response): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(input);
      const path = new URL(request.url).pathname;
      if (path === "/.well-known/openid-configuration") {
        return json(discovery);
      }
      if (path === "/.well-known/jwks.json") return response();
      return new Response(null, { status: 404 });
    }),
  );
}

function lazyByteStream(
  totalBytes: number,
  chunkBytes: number,
): {
  cancelled: () => boolean;
  pulls: () => number;
  stream: ReadableStream<Uint8Array>;
} {
  let emitted = 0;
  let pullCount = 0;
  let wasCancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    cancel() {
      wasCancelled = true;
    },
    pull(controller) {
      pullCount += 1;
      if (emitted >= totalBytes) {
        controller.close();
        return;
      }
      const size = Math.min(chunkBytes, totalBytes - emitted);
      emitted += size;
      controller.enqueue(new Uint8Array(size).fill(0x20));
    },
  });
  return {
    cancelled: () => wasCancelled,
    pulls: () => pullCount,
    stream,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("OIDC test relying party", () => {
  it.each([undefined, null, "", 0, false])(
    "rejects a validated ID token without a nonempty sid (%s)",
    (sid) => {
      expect(() => requireCentralSessionId({ sid })).toThrow(
        "Validated ID token did not contain a central session ID",
      );
    },
  );

  it("preserves a validated central sid exactly", () => {
    const sid = "central-session-id";
    expect(requireCentralSessionId({ sid })).toBe(sid);
  });

  it("structurally rejects an RP session whose central sid is null", async () => {
    const now = new Date();
    await expect(
      env.TEST_RP_DB.prepare(
        `INSERT INTO rp_session
          (id, token_hash, subject, central_session_id, display_name, email,
           expires_at, created_at, last_seen_at)
         VALUES (?, ?, ?, NULL, NULL, NULL, ?, ?, ?)`,
      )
        .bind(
          crypto.randomUUID(),
          await sessionTokenHash("legacy-null-sid-session-token"),
          crypto.randomUUID(),
          new Date(now.getTime() + 60_000).toISOString(),
          now.toISOString(),
          now.toISOString(),
        )
        .run(),
    ).rejects.toThrow("NOT NULL constraint failed");
  });

  it("serves a hardened unauthenticated harness", async () => {
    const response = await exports.default.fetch("http://localhost:5174/");

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-security-policy")).toContain(
      "frame-ancestors 'none'",
    );
    expect(await response.text()).toContain("Authorization Code + PKCE S256");
  });

  it("creates a server-side transaction with PKCE, state, and nonce", async () => {
    const outbound = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      if (url.pathname === "/.well-known/openid-configuration") {
        return json(discovery);
      }
      return new Response(null, { status: 404 });
    });
    vi.stubGlobal("fetch", outbound);

    const response = await exports.default.fetch(
      new Request("http://localhost:5174/login", { redirect: "manual" }),
    );
    expect(response.status).toBe(302);
    expect(response.headers.get("set-cookie")).toContain("HttpOnly");

    const location = new URL(response.headers.get("location") ?? "");
    expect(location.origin).toBe("http://localhost:5173");
    expect(location.pathname).toBe("/oauth2/authorize");
    expect(location.searchParams.get("code_challenge_method")).toBe("S256");
    expect(location.searchParams.get("state")).toHaveLength(43);
    expect(location.searchParams.get("nonce")).toHaveLength(43);

    const transaction = await env.TEST_RP_DB.prepare(
      `SELECT code_verifier, nonce, consumed_at
         FROM oauth_transaction
        WHERE state = ?`,
    )
      .bind(location.searchParams.get("state"))
      .first<{
        code_verifier: string;
        nonce: string;
        consumed_at: string | null;
      }>();
    expect(transaction).not.toBeNull();
    expect(transaction?.code_verifier).toHaveLength(43);
    expect(transaction?.nonce).toBe(location.searchParams.get("nonce"));
    expect(transaction?.consumed_at).toBeNull();
  });

  it("accepts a signed ID token without propagating caller-controlled resources", async () => {
    const signing = await createSigningFixture();
    const subject = crypto.randomUUID();
    const centralSessionId = crypto.randomUUID();
    const server = stubSignedOidcServer(signing, {
      audience: "pg72-test-rp",
      centralSessionId,
      subject,
    });
    const resource = "https://another-resource.example/api";
    const login = await beginOidcLogin(
      `http://localhost:5174/login?resource=${encodeURIComponent(resource)}`,
    );
    server.setExpectedNonce(login.nonce);

    expect(login.authorizationUrl.searchParams.has("resource")).toBe(false);
    const response = await exports.default.fetch(
      new Request(
        callbackUrl({
          code: "valid-code",
          iss: discovery.issuer,
          state: login.state,
        }),
        { headers: { Cookie: login.cookie }, redirect: "manual" },
      ),
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("set-cookie")).toContain("pg72_test_session=");
    expect(server.requests).toEqual({ jwks: 1, token: 1, userInfo: 1 });
    const session = await env.TEST_RP_DB.prepare(
      `SELECT subject, central_session_id
         FROM rp_session
        WHERE subject = ?`,
    )
      .bind(subject)
      .first<{ central_session_id: string; subject: string }>();
    expect(session).toEqual({ central_session_id: centralSessionId, subject });
  });

  it("rejects a validly signed ID token for a different audience", async () => {
    const signing = await createSigningFixture();
    const subject = crypto.randomUUID();
    const server = stubSignedOidcServer(signing, {
      audience: "another-oidc-client",
      centralSessionId: crypto.randomUUID(),
      subject,
    });
    const sessionCountBefore = await rpSessionCount();
    const login = await beginOidcLogin();
    server.setExpectedNonce(login.nonce);

    const response = await exports.default.fetch(
      new Request(
        callbackUrl({
          code: "wrong-audience-code",
          iss: discovery.issuer,
          state: login.state,
        }),
        { headers: { Cookie: login.cookie }, redirect: "manual" },
      ),
    );

    expect(response.status).toBe(400);
    expect(await response.text()).toContain("OIDC response validation failed");
    expect(response.headers.get("set-cookie") ?? "").not.toContain(
      "pg72_test_session=",
    );
    expect(server.requests.token).toBe(1);
    expect(server.requests.userInfo).toBe(0);
    expect(await rpSessionCount()).toBe(sessionCountBefore);
    const transaction = await env.TEST_RP_DB.prepare(
      "SELECT consumed_at FROM oauth_transaction WHERE id = ?",
    )
      .bind(login.transactionId)
      .first<{ consumed_at: string | null }>();
    expect(transaction?.consumed_at).not.toBeNull();
  });

  it("fails closed on a standard authorization error before token exchange", async () => {
    let tokenRequests = 0;
    const outbound = vi.fn(async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(input);
      const url = new URL(request.url);
      if (url.pathname === "/.well-known/openid-configuration") {
        return json(discovery);
      }
      if (url.pathname === "/oauth2/token") tokenRequests += 1;
      return new Response(null, { status: 404 });
    });
    vi.stubGlobal("fetch", outbound);
    const before = await rpSessionCount();
    const login = await beginOidcLogin();
    const rejectedResource = "https://another-resource.example/api";

    // Simulate the authorization error callback independently of the provider;
    // provider-side resource rejection is covered by the SSO Worker suite.
    const response = await exports.default.fetch(
      new Request(
        callbackUrl({
          error: "invalid_target",
          error_description: `Rejected resource: ${rejectedResource}`,
          iss: discovery.issuer,
          state: login.state,
        }),
        { headers: { Cookie: login.cookie }, redirect: "manual" },
      ),
    );

    expect(response.status).toBe(400);
    const body = await response.text();
    expect(body).toContain("OIDC response validation failed");
    expect(body).not.toContain(rejectedResource);
    expect(tokenRequests).toBe(0);
    expect(await rpSessionCount()).toBe(before);
    const transaction = await env.TEST_RP_DB.prepare(
      "SELECT consumed_at FROM oauth_transaction WHERE id = ?",
    )
      .bind(login.transactionId)
      .first<{ consumed_at: string | null }>();
    expect(transaction?.consumed_at).not.toBeNull();
  });

  it("rejects a replayed callback before a second token request", async () => {
    const transactionId = crypto.randomUUID();
    const state = "state-for-replay-test";
    await env.TEST_RP_DB.prepare(
      `INSERT INTO oauth_transaction
        (id, state, code_verifier, nonce, redirect_uri, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        transactionId,
        state,
        "verifier-for-replay-test-with-more-than-43-characters-1234",
        "nonce-for-replay-test",
        "http://localhost:5174/callback",
        "2099-01-01T00:00:00.000Z",
        "2026-07-15T00:00:00.000Z",
      )
      .run();

    let tokenRequests = 0;
    const outbound = vi.fn(async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(input);
      const url = new URL(request.url);
      if (url.pathname === "/.well-known/openid-configuration") {
        return json(discovery);
      }
      if (url.pathname === "/oauth2/token") {
        tokenRequests += 1;
        return json({ error: "invalid_grant" }, 400);
      }
      return new Response(null, { status: 404 });
    });
    vi.stubGlobal("fetch", outbound);

    const callback = `http://localhost:5174/callback?code=invalid&state=${state}`;
    const request = () =>
      exports.default.fetch(
        new Request(callback, {
          headers: { Cookie: `pg72_test_tx=${transactionId}` },
        }),
      );

    const first = await request();
    expect(first.status).toBe(400);
    expect(await first.text()).toContain("OIDC response validation failed");
    expect(tokenRequests).toBe(1);

    const second = await request();
    expect(second.status).toBe(400);
    expect(await second.text()).toContain("expired or was already used");
    expect(tokenRequests).toBe(1);
  });

  it("rejects callbacks without the HttpOnly transaction cookie", async () => {
    const response = await exports.default.fetch(
      "http://localhost:5174/callback?code=x&state=y",
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain("Missing OIDC transaction cookie");
  });

  it("validates a logout token and idempotently removes every local sid session", async () => {
    const signing = await createSigningFixture();
    const sid = crypto.randomUUID();
    const untouchedSid = crypto.randomUUID();
    await seedRpSession(sid);
    await seedRpSession(sid);
    await seedRpSession(untouchedSid);
    stubSignedOidcServer(signing, {
      audience: "pg72-test-rp",
      centralSessionId: sid,
      subject: crypto.randomUUID(),
    });
    const claims = logoutClaims(sid);
    const token = await signIdToken(signing.privateKey, claims);

    expect((await postLogoutToken(token)).status).toBe(204);
    const targetCount = () =>
      env.TEST_RP_DB.prepare(
        "SELECT COUNT(*) AS count FROM rp_session WHERE central_session_id = ?",
      )
        .bind(sid)
        .first<{ count: number }>();
    const untouchedCount = () =>
      env.TEST_RP_DB.prepare(
        "SELECT COUNT(*) AS count FROM rp_session WHERE central_session_id = ?",
      )
        .bind(untouchedSid)
        .first<{ count: number }>();
    expect((await targetCount())?.count).toBe(0);
    expect((await untouchedCount())?.count).toBe(1);
    expect((await postLogoutToken(token)).status).toBe(204);
    expect((await targetCount())?.count).toBe(0);
    expect((await untouchedCount())?.count).toBe(1);

    const receipt = await env.TEST_RP_DB.prepare(
      `SELECT central_session_id, issuer, COUNT(*) AS count
         FROM backchannel_logout_receipt
        WHERE jti = ?
        GROUP BY central_session_id, issuer`,
    )
      .bind(claims.jti)
      .first<{ central_session_id: string; count: number; issuer: string }>();
    expect(receipt).toEqual({
      central_session_id: sid,
      count: 1,
      issuer: discovery.issuer,
    });
  });

  it.each([
    ["issuer", { iss: "https://attacker.example" }],
    ["audience", { aud: "another-client" }],
    ["events", { events: { "https://attacker.example/event": {} } }],
    ["nonce", { nonce: "nonce-is-forbidden" }],
    ["lifetime", { exp: Math.floor(Date.now() / 1000) + 600 }],
  ])("rejects a logout token with invalid %s", async (_name, overrides) => {
    const signing = await createSigningFixture();
    const sid = crypto.randomUUID();
    await seedRpSession(sid);
    stubSignedOidcServer(signing, {
      audience: "pg72-test-rp",
      centralSessionId: sid,
      subject: crypto.randomUUID(),
    });
    const token = await signIdToken(
      signing.privateKey,
      logoutClaims(sid, overrides),
    );

    expect((await postLogoutToken(token)).status).toBe(400);
    const remaining = await env.TEST_RP_DB.prepare(
      "SELECT COUNT(*) AS count FROM rp_session WHERE central_session_id = ?",
    )
      .bind(sid)
      .first<{ count: number }>();
    expect(remaining?.count).toBe(1);
  });

  it("rejects a reused jti that names a different sid", async () => {
    const signing = await createSigningFixture();
    const firstSid = crypto.randomUUID();
    const secondSid = crypto.randomUUID();
    const jti = crypto.randomUUID();
    await seedRpSession(firstSid);
    await seedRpSession(secondSid);
    stubSignedOidcServer(signing, {
      audience: "pg72-test-rp",
      centralSessionId: firstSid,
      subject: crypto.randomUUID(),
    });

    const first = await signIdToken(
      signing.privateKey,
      logoutClaims(firstSid, { jti }),
    );
    const conflicting = await signIdToken(
      signing.privateKey,
      logoutClaims(secondSid, { jti }),
    );
    expect((await postLogoutToken(first)).status).toBe(204);
    expect((await postLogoutToken(conflicting)).status).toBe(400);
    const secondRemaining = await env.TEST_RP_DB.prepare(
      "SELECT COUNT(*) AS count FROM rp_session WHERE central_session_id = ?",
    )
      .bind(secondSid)
      .first<{ count: number }>();
    expect(secondRemaining?.count).toBe(1);
  });

  it("rejects a logout token whose signature is not in the issuer JWKS", async () => {
    const trusted = await createSigningFixture();
    const attacker = await createSigningFixture();
    const sid = crypto.randomUUID();
    await seedRpSession(sid);
    stubSignedOidcServer(trusted, {
      audience: "pg72-test-rp",
      centralSessionId: sid,
      subject: crypto.randomUUID(),
    });
    const token = await signIdToken(attacker.privateKey, logoutClaims(sid));
    expect((await postLogoutToken(token)).status).toBe(400);
    const remaining = await env.TEST_RP_DB.prepare(
      "SELECT COUNT(*) AS count FROM rp_session WHERE central_session_id = ?",
    )
      .bind(sid)
      .first<{ count: number }>();
    expect(remaining?.count).toBe(1);
  });

  it("accepts a valid chunked JWKS without Content-Length", async () => {
    const signing = await createSigningFixture();
    const sid = crypto.randomUUID();
    await seedRpSession(sid);
    const encoded = new TextEncoder().encode(
      JSON.stringify({ keys: [signing.publicJwk] }),
    );
    stubLogoutJwksResponse(
      () =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              for (let offset = 0; offset < encoded.length; offset += 7) {
                controller.enqueue(encoded.slice(offset, offset + 7));
              }
              controller.close();
            },
          }),
          { headers: { "Content-Type": "application/json" } },
        ),
    );
    const token = await signIdToken(signing.privateKey, logoutClaims(sid));

    expect((await postLogoutToken(token)).status).toBe(204);
  });

  it("rejects a forged-small Content-Length and cancels a 32 MiB-style stream at the byte limit", async () => {
    const signing = await createSigningFixture();
    const sid = crypto.randomUUID();
    await seedRpSession(sid);
    const lazy = lazyByteStream(32 * 1024 * 1024, 1024);
    stubLogoutJwksResponse(
      () =>
        new Response(lazy.stream, {
          headers: {
            "Content-Length": "10",
            "Content-Type": "application/json",
          },
        }),
    );
    const token = await signIdToken(signing.privateKey, logoutClaims(sid));

    expect((await postLogoutToken(token)).status).toBe(400);
    expect(lazy.cancelled()).toBe(true);
    expect(lazy.pulls()).toBeLessThanOrEqual(66);
  });

  it("rejects a forged-large Content-Length before pulling and cancels the body", async () => {
    const signing = await createSigningFixture();
    const sid = crypto.randomUUID();
    await seedRpSession(sid);
    const lazy = lazyByteStream(128, 32);
    stubLogoutJwksResponse(
      () =>
        new Response(lazy.stream, {
          headers: {
            "Content-Length": String(64 * 1024 + 1),
            "Content-Type": "application/json",
          },
        }),
    );
    const token = await signIdToken(signing.privateKey, logoutClaims(sid));

    expect((await postLogoutToken(token)).status).toBe(400);
    expect(lazy.cancelled()).toBe(true);
    // WHATWG streams may prefill one chunk before the Response is inspected;
    // the bounded reader itself must not pull beyond that queued chunk.
    expect(lazy.pulls()).toBeLessThanOrEqual(1);
  });

  it("fails closed and cancels a chunked JWKS with invalid UTF-8", async () => {
    const signing = await createSigningFixture();
    const sid = crypto.randomUUID();
    await seedRpSession(sid);
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
      },
      start(controller) {
        controller.enqueue(new Uint8Array([0x7b, 0xff, 0x7d]));
      },
    });
    stubLogoutJwksResponse(
      () => new Response(stream, { headers: { "Content-Type": "application/json" } }),
    );
    const token = await signIdToken(signing.privateKey, logoutClaims(sid));

    expect((await postLogoutToken(token)).status).toBe(400);
    expect(cancelled).toBe(true);
  });

  it("rejects malformed back-channel requests before token validation", async () => {
    const wrongMediaType = await exports.default.fetch(
      new Request("http://localhost:5174/backchannel-logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logout_token: "not-a-token" }),
      }),
    );
    expect(wrongMediaType.status).toBe(415);

    const duplicated = await exports.default.fetch(
      new Request("http://localhost:5174/backchannel-logout", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "logout_token=a&logout_token=b",
      }),
    );
    expect(duplicated.status).toBe(400);
  });
});
