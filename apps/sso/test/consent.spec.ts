import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import {
  continueCurrentAccountSelection,
  createAuthenticatedUser,
} from "./helpers";

interface ConsentClientInfo {
  clientId: string;
  name: string;
  developerName: string | null;
  privacyPolicyUrl: string | null;
  termsOfServiceUrl: string | null;
  redirectHosts: string[];
  scopes: string[];
}

async function insertClient(options: {
  clientId: string;
  name?: string;
  scopes?: string[];
  redirectUris?: string[];
  disabled?: boolean;
  tos?: string | null;
  policy?: string | null;
  metadata?: string | null;
}): Promise<void> {
  const now = new Date().toISOString();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO oauthClient (
      id, clientId, disabled, skipConsent, scopes, createdAt, updatedAt, name,
      redirectUris, tokenEndpointAuthMethod, grantTypes, responseTypes,
      public, requirePKCE, tos, policy, metadata
    ) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, 'none', ?, '["code"]', 1, 1, ?, ?, ?)`,
  )
    .bind(
      crypto.randomUUID(),
      options.clientId,
      options.disabled ? 1 : 0,
      JSON.stringify(options.scopes ?? ["openid", "profile", "email"]),
      now,
      now,
      options.name ?? "Consent Surface Test",
      JSON.stringify(
        options.redirectUris ?? ["https://consent.example/callback"],
      ),
      '["authorization_code"]',
      options.tos ?? null,
      options.policy ?? null,
      options.metadata ?? null,
    )
    .run();
}

function authorizeQuery(
  clientId: string,
  redirectUri: string,
  scope: string,
): URLSearchParams {
  return new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope,
    code_challenge: "A".repeat(43),
    code_challenge_method: "S256",
    state: "B".repeat(43),
    nonce: "C".repeat(43),
  });
}

describe("OAuth consent surface", () => {
  it("requires a session for consent client info", async () => {
    const response = await exports.default.fetch(
      "http://localhost:5173/api/consent/client?client_id=pg72-test-rp",
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "unauthorized" });
  });

  it("serves consent client identity exclusively from the D1 registration", async () => {
    const clientId = `consent-info-${crypto.randomUUID()}`;
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await insertClient({
      clientId,
      name: "Copy",
      scopes: ["openid", "profile", "email", "offline_access"],
      redirectUris: [
        "https://copy.example/callback",
        "https://copy.example/callback/alt",
        "http://localhost:5174/callback",
      ],
      tos: "https://copy.example/terms",
      policy: "https://copy.example/privacy",
      metadata: JSON.stringify({
        developer_name: "PG72 Copy Team",
        backchannel_logout_uri: "https://copy.example/api/auth/backchannel-logout",
      }),
    });

    // Spoofed presentation parameters in the query string must be ignored;
    // only client_id selects the D1 row.
    const query = new URLSearchParams({
      client_id: clientId,
      client_name: "Evil App",
      developer_name: "Evil Developer",
      redirect_uri: "https://evil.example/callback",
      tos_uri: "http://evil.example/terms",
    });
    const response = await exports.default.fetch(
      new Request(`http://localhost:5173/api/consent/client?${query}`, {
        headers,
      }),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = await response.text();
    const { client } = JSON.parse(body) as { client: ConsentClientInfo };
    expect(client).toEqual({
      clientId,
      name: "Copy",
      developerName: "PG72 Copy Team",
      privacyPolicyUrl: "https://copy.example/privacy",
      termsOfServiceUrl: "https://copy.example/terms",
      redirectHosts: ["copy.example", "localhost:5174"],
      scopes: ["openid", "profile", "email", "offline_access"],
    });
    expect(body).not.toContain("Evil");
    expect(body).not.toContain("evil.example");
    // Provider-internal metadata never leaks to the consent screen.
    expect(body).not.toContain("backchannel_logout_uri");
  });

  it("hides unknown and disabled clients from the consent surface", async () => {
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    const unknown = await exports.default.fetch(
      new Request(
        `http://localhost:5173/api/consent/client?client_id=missing-${crypto.randomUUID()}`,
        { headers },
      ),
    );
    expect(unknown.status).toBe(404);

    const disabledClientId = `consent-disabled-${crypto.randomUUID()}`;
    await insertClient({ clientId: disabledClientId, disabled: true });
    const disabled = await exports.default.fetch(
      new Request(
        `http://localhost:5173/api/consent/client?client_id=${disabledClientId}`,
        { headers },
      ),
    );
    expect(disabled.status).toBe(404);
    expect(await disabled.json()).toEqual({ error: "client_not_found" });
  });

  it("sanitizes trust URLs and malformed metadata on read", async () => {
    const clientId = `consent-dirty-${crypto.randomUUID()}`;
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    // Rows written outside the admin API must never surface unsafe links.
    await insertClient({
      clientId,
      tos: "http://insecure.example/terms",
      policy: "https://user:secret@copy.example/privacy",
      metadata: "not-json",
    });

    const response = await exports.default.fetch(
      new Request(
        `http://localhost:5173/api/consent/client?client_id=${clientId}`,
        { headers },
      ),
    );
    expect(response.status).toBe(200);
    const { client } = (await response.json()) as { client: ConsentClientInfo };
    expect(client.termsOfServiceUrl).toBeNull();
    expect(client.privacyPolicyUrl).toBeNull();
    expect(client.developerName).toBeNull();
  });

  it("rejects authorization requests for scopes outside the client registration", async () => {
    const clientId = `consent-scope-subset-${crypto.randomUUID()}`;
    const redirectUri = "https://subset.example/callback";
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await insertClient({
      clientId,
      scopes: ["openid", "profile", "email"],
      redirectUris: [redirectUri],
    });

    const response = await exports.default.fetch(
      new Request(
        `http://localhost:5173/oauth2/authorize?${authorizeQuery(
          clientId,
          redirectUri,
          "openid profile email offline_access",
        )}`,
        { headers: new Headers(headers), redirect: "manual" },
      ),
    );

    // The provider enforces the subset before any consent interaction: the
    // browser is sent back to the relying party with invalid_scope instead
    // of reaching the consent screen.
    expect(response.status).toBe(302);
    const location = new URL(
      response.headers.get("location") ?? "",
      "http://localhost:5173",
    );
    expect(`${location.origin}${location.pathname}`).toBe(redirectUri);
    expect(location.searchParams.get("error")).toBe("invalid_scope");
    expect(location.searchParams.get("state")).toBe("B".repeat(43));
    expect(location.pathname).not.toBe("/consent");
  });

  it("returns access_denied to the relying party when the user cancels", async () => {
    const clientId = `consent-cancel-${crypto.randomUUID()}`;
    const redirectUri = "https://cancel.example/callback";
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await insertClient({ clientId, redirectUris: [redirectUri] });

    const authorizeResponse = await continueCurrentAccountSelection(
      await exports.default.fetch(
        new Request(
          `http://localhost:5173/oauth2/authorize?${authorizeQuery(
            clientId,
            redirectUri,
            "openid profile email",
          )}`,
          { headers, redirect: "manual" },
        ),
      ),
      headers,
    );
    expect(authorizeResponse.status).toBe(302);
    const consentLocation = new URL(
      authorizeResponse.headers.get("location") ?? "",
      "http://localhost:5173",
    );
    expect(consentLocation.pathname).toBe("/consent");

    const consentHeaders = new Headers(headers);
    consentHeaders.set("Sec-Fetch-Mode", "cors");
    const denyResponse = await exports.default.fetch(
      new Request("http://localhost:5173/oauth2/consent", {
        method: "POST",
        headers: consentHeaders,
        body: JSON.stringify({
          accept: false,
          oauth_query: consentLocation.search.slice(1),
        }),
      }),
    );

    expect(denyResponse.status).toBe(200);
    const result = (await denyResponse.json()) as {
      redirect?: boolean;
      url?: string;
    };
    expect(result.redirect).toBe(true);
    const redirect = new URL(result.url ?? "");
    expect(`${redirect.origin}${redirect.pathname}`).toBe(redirectUri);
    expect(redirect.searchParams.get("error")).toBe("access_denied");
    expect(redirect.searchParams.get("state")).toBe("B".repeat(43));
    expect(redirect.searchParams.has("code")).toBe(false);

    // Denying never records a consent grant.
    const consents = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM oauthConsent WHERE clientId = ? AND userId = ?",
    )
      .bind(clientId, userId)
      .first<{ count: number }>();
    expect(consents?.count).toBe(0);
  });

  it("rejects consent decisions whose signed query was tampered with", async () => {
    const clientId = `consent-tamper-${crypto.randomUUID()}`;
    const otherClientId = `consent-tamper-other-${crypto.randomUUID()}`;
    const redirectUri = "https://tamper.example/callback";
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await insertClient({ clientId, redirectUris: [redirectUri] });
    await insertClient({ clientId: otherClientId, redirectUris: [redirectUri] });

    const authorizeResponse = await continueCurrentAccountSelection(
      await exports.default.fetch(
        new Request(
          `http://localhost:5173/oauth2/authorize?${authorizeQuery(
            clientId,
            redirectUri,
            "openid profile email",
          )}`,
          { headers, redirect: "manual" },
        ),
      ),
      headers,
    );
    const consentLocation = new URL(
      authorizeResponse.headers.get("location") ?? "",
      "http://localhost:5173",
    );
    expect(consentLocation.pathname).toBe("/consent");

    // Swap the signed client_id for another registered client. The HMAC over
    // the canonical query no longer matches, so the decision is rejected.
    const tampered = new URLSearchParams(consentLocation.search.slice(1));
    tampered.set("client_id", otherClientId);

    const consentHeaders = new Headers(headers);
    consentHeaders.set("Sec-Fetch-Mode", "cors");
    const response = await exports.default.fetch(
      new Request("http://localhost:5173/oauth2/consent", {
        method: "POST",
        headers: consentHeaders,
        body: JSON.stringify({
          accept: true,
          oauth_query: tampered.toString(),
        }),
      }),
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_signature" });
    const consents = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM oauthConsent WHERE userId = ?",
    )
      .bind(userId)
      .first<{ count: number }>();
    expect(consents?.count).toBe(0);
  });

  it("keeps the migration backfill compatible with existing client metadata", async () => {
    const now = new Date().toISOString();
    await env.PG72_ID_DB.prepare(
      "DELETE FROM oauthClient WHERE clientId IN ('pg72-diary', 'pg72-copy')",
    ).run();
    await env.PG72_ID_DB.batch([
      // Diary-style row that already stores provider metadata.
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthClient (
          id, clientId, skipConsent, scopes, createdAt, updatedAt, name,
          redirectUris, metadata
        ) VALUES (?, 'pg72-diary', 0, ?, ?, ?, 'PG72 Diary', ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        '["openid","profile","email"]',
        now,
        now,
        '["https://diary.pg72.tw/api/auth/callback"]',
        '{"backchannel_logout_uri":"https://diary.pg72.tw/api/auth/backchannel-logout"}',
      ),
      // Copy-style row without any metadata.
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthClient (
          id, clientId, skipConsent, scopes, createdAt, updatedAt, name,
          redirectUris, metadata
        ) VALUES (?, 'pg72-copy', 0, ?, ?, ?, 'PG72 Copy', ?, NULL)`,
      ).bind(
        crypto.randomUUID(),
        '["openid","profile","email"]',
        now,
        now,
        '["https://copy.pg72.tw/api/auth/callback/pg72-id"]',
      ),
    ]);

    const migration = env.TEST_MIGRATIONS.find(
      ({ name }) => name === "0010_client_trust_metadata.sql",
    );
    if (!migration) {
      throw new Error("Missing test migration: 0010_client_trust_metadata.sql");
    }
    await env.PG72_ID_DB.batch(
      migration.queries.map((query) => env.PG72_ID_DB.prepare(query)),
    );

    const rows = await env.PG72_ID_DB.prepare(
      `SELECT clientId, metadata FROM oauthClient
        WHERE clientId IN ('pg72-diary', 'pg72-copy')
        ORDER BY clientId`,
    ).all<{ clientId: string; metadata: string }>();
    expect(rows.results).toHaveLength(2);
    expect(JSON.parse(rows.results[0]?.metadata ?? "{}")).toEqual({
      developer_name: "PG72 官方",
    });
    expect(JSON.parse(rows.results[1]?.metadata ?? "{}")).toEqual({
      backchannel_logout_uri: "https://diary.pg72.tw/api/auth/backchannel-logout",
      developer_name: "PG72 官方",
    });
  });
});
