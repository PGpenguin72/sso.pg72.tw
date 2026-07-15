import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";

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

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("OIDC test relying party", () => {
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
