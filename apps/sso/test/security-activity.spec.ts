import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import { createAuthenticatedUser } from "./helpers";

const BASE_URL = "http://localhost:5173";

async function insertAudit(options: {
  eventType: string;
  subjectId: string | null;
  occurredAt: string;
  metadata?: Record<string, string> | null;
}): Promise<void> {
  await env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, subject_id, outcome, metadata_json, occurred_at)
     VALUES (?, ?, ?, 'success', ?, ?)`,
  )
    .bind(
      crypto.randomUUID(),
      options.eventType,
      options.subjectId,
      options.metadata ? JSON.stringify(options.metadata) : null,
      options.occurredAt,
    )
    .run();
}

describe("security activity feed", () => {
  it("requires an active session", async () => {
    const response = await exports.default.fetch(
      `${BASE_URL}/api/account/security-activity`,
    );
    expect(response.status).toBe(401);
  });

  it("returns only the caller's own allow-listed events with summaries", async () => {
    const owner = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const other = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    await insertAudit({
      eventType: "user.login_succeeded",
      subjectId: owner.userId,
      occurredAt: "2026-07-01T00:00:00.000Z",
      metadata: { provider: "google", device: "desktop" },
    });
    await insertAudit({
      eventType: "user.avatar_updated",
      subjectId: owner.userId,
      occurredAt: "2026-07-02T00:00:00.000Z",
    });
    // Not in the self-activity allow-list -> must be filtered out.
    await insertAudit({
      eventType: "admin.users_listed",
      subjectId: owner.userId,
      occurredAt: "2026-07-03T00:00:00.000Z",
    });
    // Belongs to a different user -> must never appear for the owner.
    await insertAudit({
      eventType: "user.login_succeeded",
      subjectId: other.userId,
      occurredAt: "2026-07-04T00:00:00.000Z",
      metadata: { provider: "passkey" },
    });

    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/security-activity`, {
        headers: owner.headers,
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      events: { type: string; at: string; summary: string; provider?: string }[];
      nextCursor?: string;
    };
    const types = body.events.map((event) => event.type);
    expect(types).toContain("user.login_succeeded");
    expect(types).toContain("user.avatar_updated");
    expect(types).not.toContain("admin.users_listed");

    const login = body.events.find(
      (event) => event.type === "user.login_succeeded",
    );
    expect(login?.provider).toBe("google");
    expect(login?.summary).toBe("登入成功");
  });

  it("paginates with a keyset cursor", async () => {
    const owner = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    for (let i = 0; i < 30; i += 1) {
      await insertAudit({
        eventType: "user.login_succeeded",
        subjectId: owner.userId,
        occurredAt: new Date(Date.UTC(2026, 5, 1, 0, 0, i)).toISOString(),
        metadata: { provider: "google" },
      });
    }

    const first = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/security-activity`, {
        headers: owner.headers,
      }),
    );
    const firstBody = (await first.json()) as {
      events: { id: string }[];
      nextCursor?: string;
    };
    expect(firstBody.events.length).toBe(25);
    expect(typeof firstBody.nextCursor).toBe("string");

    const second = await exports.default.fetch(
      new Request(
        `${BASE_URL}/api/account/security-activity?cursor=${encodeURIComponent(firstBody.nextCursor ?? "")}`,
        { headers: owner.headers },
      ),
    );
    const secondBody = (await second.json()) as { events: { id: string }[] };
    expect(secondBody.events.length).toBeGreaterThanOrEqual(5);

    // No overlap between the two pages.
    const firstIds = new Set(firstBody.events.map((event) => event.id));
    for (const event of secondBody.events) {
      expect(firstIds.has(event.id)).toBe(false);
    }
  });

  it("rejects a malformed cursor", async () => {
    const owner = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/security-activity?cursor=!!!not-valid`, {
        headers: owner.headers,
      }),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_cursor" });
  });
});
