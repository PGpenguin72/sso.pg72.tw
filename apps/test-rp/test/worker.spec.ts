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

  it("does not resume a legacy RP session whose central sid is null", async () => {
    const token = "legacy-null-sid-session-token";
    const now = new Date();
    await env.TEST_RP_DB.prepare(
      `INSERT INTO rp_session
        (id, token_hash, subject, central_session_id, display_name, email,
         expires_at, created_at, last_seen_at)
       VALUES (?, ?, ?, NULL, NULL, NULL, ?, ?, ?)`,
    )
      .bind(
        crypto.randomUUID(),
        await sessionTokenHash(token),
        crypto.randomUUID(),
        new Date(now.getTime() + 60_000).toISOString(),
        now.toISOString(),
        now.toISOString(),
      )
      .run();

    const response = await exports.default.fetch(
      new Request("http://localhost:5174/", {
        headers: { Cookie: `pg72_test_session=${token}` },
      }),
    );
    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).toContain("PGID protocol check");
    expect(body).not.toContain("OIDC session established");
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
});
