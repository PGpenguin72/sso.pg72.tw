import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

describe("bounded test-RP readiness profile", () => {
  it("keeps health and invalid callbacks deterministic without session writes", async () => {
    const responses = await Promise.all(
      Array.from({ length: 20 }, (_value, index) =>
        exports.default.fetch(
          new Request(
            index % 2 === 0
              ? "http://localhost:5174/health"
              : "http://localhost:5174/callback",
          ),
        ),
      ),
    );
    expect(responses.filter(({ status }) => status === 200)).toHaveLength(10);
    expect(responses.filter(({ status }) => status === 400)).toHaveLength(10);

    const state = await env.TEST_RP_DB.prepare(
      `SELECT
        (SELECT COUNT(*) FROM rp_session) AS sessions,
        (SELECT COUNT(*) FROM oauth_transaction) AS transactions,
        (SELECT COUNT(*) FROM backchannel_logout_receipt) AS logout_receipts`,
    ).first<{
      logout_receipts: number;
      sessions: number;
      transactions: number;
    }>();
    expect(state).toEqual({ logout_receipts: 0, sessions: 0, transactions: 0 });
  });
});
