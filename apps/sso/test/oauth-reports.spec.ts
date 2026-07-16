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
  interposeAfterD1First,
} from "./helpers";

const BASE_URL = "http://localhost:5173";

async function insertClient(clientId: string): Promise<void> {
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
      JSON.stringify(["openid", "profile", "email"]),
      now,
      now,
      "Reported App",
      JSON.stringify(["https://report.example/callback"]),
      '["authorization_code"]',
    )
    .run();
}

describe("oauth client reports", () => {
  it("accepts a report from a signed-in user and audits it", async () => {
    const clientId = `report-${crypto.randomUUID()}`;
    await insertClient(clientId);
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/oauth/report`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          clientId,
          reason: "phishing",
          detail: "Pretends to be the official login.",
        }),
      }),
    );
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ reported: true });

    const row = await env.PG72_ID_DB.prepare(
      "SELECT reporter_user_id, reason, status, detail FROM oauth_client_report WHERE client_id = ?",
    )
      .bind(clientId)
      .first<{
        reporter_user_id: string;
        reason: string;
        status: string;
        detail: string;
      }>();
    expect(row).toMatchObject({
      reporter_user_id: userId,
      reason: "phishing",
      status: "open",
    });

    const audit = await env.PG72_ID_DB.prepare(
      `SELECT event_type, metadata_json FROM audit_event
        WHERE event_type = 'oauth_client.reported' AND client_id = ?
        ORDER BY occurred_at DESC LIMIT 1`,
    )
      .bind(clientId)
      .first<{ event_type: string; metadata_json: string }>();
    expect(audit?.event_type).toBe("oauth_client.reported");
    // Free-text detail must never reach the audit metadata.
    expect(audit?.metadata_json).toBe(JSON.stringify({ reason: "phishing" }));
  });

  it("validates the reason, detail length, and target client", async () => {
    const clientId = `report-valid-${crypto.randomUUID()}`;
    await insertClient(clientId);
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    const badReason = await exports.default.fetch(
      new Request(`${BASE_URL}/api/oauth/report`, {
        method: "POST",
        headers,
        body: JSON.stringify({ clientId, reason: "nonsense" }),
      }),
    );
    expect(badReason.status).toBe(400);
    expect(await badReason.json()).toEqual({ error: "invalid_report" });

    const longDetail = await exports.default.fetch(
      new Request(`${BASE_URL}/api/oauth/report`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          clientId,
          reason: "other",
          detail: "x".repeat(1001),
        }),
      }),
    );
    expect(longDetail.status).toBe(400);
    expect(await longDetail.json()).toEqual({ error: "invalid_detail" });

    const unknownClient = await exports.default.fetch(
      new Request(`${BASE_URL}/api/oauth/report`, {
        method: "POST",
        headers,
        body: JSON.stringify({ clientId: "does-not-exist", reason: "other" }),
      }),
    );
    expect(unknownClient.status).toBe(404);
  });

  it("rejects unauthenticated and cross-origin reports", async () => {
    const clientId = `report-origin-${crypto.randomUUID()}`;
    await insertClient(clientId);
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    const unauthenticated = await exports.default.fetch(
      new Request(`${BASE_URL}/api/oauth/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: BASE_URL },
        body: JSON.stringify({ clientId, reason: "other" }),
      }),
    );
    expect(unauthenticated.status).toBe(401);

    const crossOrigin = new Headers(headers);
    crossOrigin.set("Origin", "https://attacker.example");
    const rejected = await exports.default.fetch(
      new Request(`${BASE_URL}/api/oauth/report`, {
        method: "POST",
        headers: crossOrigin,
        body: JSON.stringify({ clientId, reason: "other" }),
      }),
    );
    expect(rejected.status).toBe(403);
  });

  it("lets an admin list and resolve reports but forbids non-admins", async () => {
    const clientId = `report-admin-${crypto.randomUUID()}`;
    await insertClient(clientId);
    const reporter = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const submit = await exports.default.fetch(
      new Request(`${BASE_URL}/api/oauth/report`, {
        method: "POST",
        headers: reporter.headers,
        body: JSON.stringify({ clientId, reason: "impersonation" }),
      }),
    );
    expect(submit.status).toBe(202);

    // A developer (clients.manage but not clients.manage_all) is forbidden.
    const developer = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "developer",
    );
    const forbidden = await exports.default.fetch(
      new Request(`${BASE_URL}/api/admin/oauth-reports`, {
        headers: developer.headers,
      }),
    );
    expect(forbidden.status).toBe(403);

    const admin = await createBootstrapAdmin();
    const list = await exports.default.fetch(
      new Request(`${BASE_URL}/api/admin/oauth-reports?status=open`, {
        headers: admin.headers,
      }),
    );
    expect(list.status).toBe(200);
    const body = (await list.json()) as {
      reports: { id: string; clientId: string; status: string }[];
    };
    const report = body.reports.find((entry) => entry.clientId === clientId);
    expect(report).toBeDefined();
    expect(report?.status).toBe("open");

    const resolve = await exports.default.fetch(
      new Request(`${BASE_URL}/api/admin/oauth-reports/${report?.id}/resolve`, {
        method: "POST",
        headers: admin.headers,
      }),
    );
    expect(resolve.status).toBe(200);
    expect(await resolve.json()).toMatchObject({ resolved: true, id: report?.id });

    // Resolving an already-resolved report is a state-conflict no-op.
    const again = await exports.default.fetch(
      new Request(`${BASE_URL}/api/admin/oauth-reports/${report?.id}/resolve`, {
        method: "POST",
        headers: admin.headers,
      }),
    );
    expect(again.status).toBe(409);
    expect(await again.json()).toEqual({ error: "management_state_changed" });

    const stored = await env.PG72_ID_DB.prepare(
      "SELECT status, resolved_by_user_id FROM oauth_client_report WHERE id = ?",
    )
      .bind(report?.id)
      .first<{ status: string; resolved_by_user_id: string }>();
    expect(stored?.status).toBe("resolved");
    expect(stored?.resolved_by_user_id).toBe(admin.userId);
  });

  it("revalidates the admin account before resolving a report", async () => {
    const reportId = crypto.randomUUID();
    const clientId = `report-commit-${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO oauth_client_report
        (id, reporter_user_id, client_id, reason, status, created_at)
       VALUES (?, NULL, ?, 'other', 'open', ?)`,
    )
      .bind(reportId, clientId, now)
      .run();
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const interposed = interposeAfterD1First(
      "SELECT email, role, status, accessLevel",
      async () => {
        await env.PG72_ID_DB.prepare(
          "UPDATE user SET accessLevel = 'restricted', role = 'user' WHERE id = ?",
        )
          .bind(admin.userId)
          .run();
      },
    );
    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${BASE_URL}/api/admin/oauth-reports/${reportId}/resolve`, {
        method: "POST",
        headers: admin.headers,
      }),
      { ...env, PG72_ID_DB: interposed.database } as Env,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(interposed.wasIntercepted()).toBe(true);
    expect(response.status).toBe(409);
    const report = await env.PG72_ID_DB.prepare(
      "SELECT status, resolved_at FROM oauth_client_report WHERE id = ?",
    )
      .bind(reportId)
      .first<{ resolved_at: string | null; status: string }>();
    expect(report).toEqual({ status: "open", resolved_at: null });
    const audit = await env.PG72_ID_DB.prepare(
      `SELECT COUNT(*) AS count FROM audit_event
        WHERE event_type = 'oauth_client.report_resolved'
          AND subject_id = ? AND outcome = 'success'`,
    )
      .bind(reportId)
      .first<{ count: number }>();
    expect(audit?.count).toBe(0);
  });

  it("paginates reports with a keyset cursor", async () => {
    const admin = await createBootstrapAdmin();
    const clientId = `report-page-${crypto.randomUUID()}`;
    await insertClient(clientId);

    // Insert 27 reports for this client directly (deterministic timestamps).
    for (let i = 0; i < 27; i += 1) {
      await env.PG72_ID_DB.prepare(
        `INSERT INTO oauth_client_report
          (id, reporter_user_id, client_id, reason, status, created_at)
         VALUES (?, NULL, ?, 'other', 'open', ?)`,
      )
        .bind(
          crypto.randomUUID(),
          clientId,
          new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
        )
        .run();
    }

    const first = await exports.default.fetch(
      new Request(`${BASE_URL}/api/admin/oauth-reports`, {
        headers: admin.headers,
      }),
    );
    const firstBody = (await first.json()) as {
      reports: unknown[];
      nextCursor?: string;
    };
    expect(firstBody.reports.length).toBe(25);
    expect(typeof firstBody.nextCursor).toBe("string");

    const second = await exports.default.fetch(
      new Request(
        `${BASE_URL}/api/admin/oauth-reports?cursor=${encodeURIComponent(firstBody.nextCursor ?? "")}`,
        { headers: admin.headers },
      ),
    );
    const secondBody = (await second.json()) as { reports: unknown[] };
    // At least the remaining reports for this client appear on page two.
    expect(secondBody.reports.length).toBeGreaterThanOrEqual(2);
  });
});
