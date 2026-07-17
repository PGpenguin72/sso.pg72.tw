import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

describe("test-RP continuity schema", () => {
  it("round-trips the immutable subject and central sid without token material", async () => {
    const now = new Date();
    const fixture = {
      centralSessionId: crypto.randomUUID(),
      id: crypto.randomUUID(),
      subject: crypto.randomUUID(),
      tokenHash: crypto.randomUUID().replaceAll("-", ""),
    };
    await env.TEST_RP_DB.prepare(
      `INSERT INTO rp_session
        (id, token_hash, subject, central_session_id, display_name, email,
         expires_at, created_at, last_seen_at)
       VALUES (?, ?, ?, ?, NULL, NULL, ?, ?, ?)`,
    )
      .bind(
        fixture.id,
        fixture.tokenHash,
        fixture.subject,
        fixture.centralSessionId,
        new Date(now.getTime() + 60_000).toISOString(),
        now.toISOString(),
        now.toISOString(),
      )
      .run();
    const restored = await env.TEST_RP_DB.prepare(
      `SELECT id, subject, central_session_id
         FROM rp_session
        WHERE id = ?`,
    )
      .bind(fixture.id)
      .first<{
        central_session_id: string;
        id: string;
        subject: string;
      }>();
    expect(restored).toEqual({
      central_session_id: fixture.centralSessionId,
      id: fixture.id,
      subject: fixture.subject,
    });
    expect(restored).not.toHaveProperty("token_hash");

    const foreignKeys = await env.TEST_RP_DB.prepare(
      "PRAGMA foreign_key_check",
    ).all();
    expect(foreignKeys.results).toEqual([]);
  });
});
