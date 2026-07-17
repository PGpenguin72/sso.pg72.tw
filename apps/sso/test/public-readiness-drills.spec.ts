import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

describe("bounded public-readiness request profile", () => {
  it("keeps concurrent unauthenticated probes within closed expected statuses", async () => {
    const definitions = [
      { path: "/health", status: 200 },
      { path: "/.well-known/openid-configuration", status: 200 },
      { path: "/oauth2/authorize", status: 400 },
      { path: "/oauth2/userinfo", status: 401 },
      { path: "/api/admin/users", status: 401 },
    ];
    const requests = Array.from({ length: 20 }, async (_value, index) => {
      const definition = definitions[index % definitions.length];
      const response = await exports.default.fetch(
        new Request(`http://localhost:5173${definition.path}`),
      );
      return { expected: definition.status, status: response.status };
    });
    const results = await Promise.all(requests);
    expect(results.every(({ expected, status }) => status === expected)).toBe(true);

    const sourceRows = await env.PG72_ID_DB.prepare(
      `SELECT
        (SELECT COUNT(*) FROM user) AS users,
        (SELECT COUNT(*) FROM session) AS sessions,
        (SELECT COUNT(*) FROM oauthAccessToken) AS access_tokens,
        (SELECT COUNT(*) FROM oauthRefreshToken) AS refresh_tokens`,
    ).first<{
      access_tokens: number;
      refresh_tokens: number;
      sessions: number;
      users: number;
    }>();
    expect(sourceRows).toEqual({
      access_tokens: 0,
      refresh_tokens: 0,
      sessions: 0,
      users: 0,
    });
  });
});
