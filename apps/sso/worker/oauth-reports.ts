import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";

import { requireAdminPermission } from "./admin-gate";
import {
  auditEventMutationCommitted,
  auditInsertForOpenOAuthReportStatement,
  createAuditEvent,
  enqueueSecurityEvent,
  recordAudit,
} from "./audit";
import { createAuth } from "./auth";
import { readRuntimeConfig } from "./config";

type AppEnv = { Bindings: Env };

const REPORT_REASONS = new Set([
  "impersonation",
  "phishing",
  "scope_abuse",
  "other",
]);
const DETAIL_MAX_LENGTH = 1000;
const CLIENT_ID_MAX_LENGTH = 256;
const REPORTS_PER_PAGE = 25;

interface ReportInput {
  clientId?: unknown;
  reason?: unknown;
  detail?: unknown;
}

interface ReportRow {
  id: string;
  reporter_user_id: string | null;
  client_id: string;
  reason: string;
  detail: string | null;
  status: string;
  created_at: string;
  resolved_at: string | null;
  resolved_by_user_id: string | null;
}

async function readJson<T>(request: Request): Promise<T | null> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    return null;
  }
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  );
}

function encodeCursor(createdAt: string, id: string): string {
  return btoa(`${createdAt}|${id}`)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function decodeCursor(cursor: string): { createdAt: string; id: string } | null {
  if (cursor.length > 256 || !/^[A-Za-z0-9_-]+$/.test(cursor)) return null;
  try {
    const decoded = atob(cursor.replaceAll("-", "+").replaceAll("_", "/"));
    const separator = decoded.indexOf("|");
    if (separator <= 0) return null;
    const createdAt = decoded.slice(0, separator);
    const id = decoded.slice(separator + 1);
    if (!createdAt || !id) return null;
    return { createdAt, id };
  } catch {
    return null;
  }
}

/**
 * Public (session-required) client abuse report endpoint. Mounted at the root
 * so it owns its own Origin and body-size guards; the /api/admin routes below
 * inherit the shared admin middleware in worker/index.ts.
 */
export const oauthReportRoutes = new Hono<AppEnv>();

oauthReportRoutes.use(
  "/api/oauth/report",
  bodyLimit({
    maxSize: 8 * 1024,
    onError: (c) => c.json({ error: "request_too_large" }, 413),
  }),
);
oauthReportRoutes.use("/api/oauth/report", async (c, next) => {
  const config = readRuntimeConfig(c.env);
  if (c.req.header("origin") !== config.authBaseUrl) {
    return c.json({ error: "invalid_origin" }, 403);
  }
  await next();
});

oauthReportRoutes.post("/api/oauth/report", async (c) => {
  const auth = createAuth(c.env, c.executionCtx);
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session || session.user.status !== "active") {
    return c.json({ error: "unauthorized" }, 401);
  }

  const rateLimit = await c.env.AUTH_RATE_LIMITER.limit({ key: session.user.id });
  if (!rateLimit.success) {
    return c.json({ error: "rate_limited" }, 429);
  }

  const input = await readJson<ReportInput>(c.req.raw);
  const clientId = typeof input?.clientId === "string" ? input.clientId : "";
  const reason = typeof input?.reason === "string" ? input.reason : "";
  if (!clientId || clientId.length > CLIENT_ID_MAX_LENGTH || !REPORT_REASONS.has(reason)) {
    return c.json({ error: "invalid_report" }, 400);
  }
  let detail: string | null = null;
  if (input?.detail !== undefined && input.detail !== null) {
    if (typeof input.detail !== "string" || input.detail.length > DETAIL_MAX_LENGTH) {
      return c.json({ error: "invalid_detail" }, 400);
    }
    const trimmed = input.detail.trim();
    detail = trimmed.length > 0 ? trimmed : null;
  }

  // The report must name a real client the user could have seen; this also
  // keeps the table free of junk client ids.
  const client = await c.env.PG72_ID_DB.prepare(
    "SELECT clientId FROM oauthClient WHERE clientId = ? LIMIT 1",
  )
    .bind(clientId)
    .first<{ clientId: string }>();
  if (!client) {
    return c.json({ error: "client_not_found" }, 404);
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await c.env.PG72_ID_DB.prepare(
    `INSERT INTO oauth_client_report
      (id, reporter_user_id, client_id, reason, detail, status, created_at)
     VALUES (?, ?, ?, ?, ?, 'open', ?)`,
  )
    .bind(id, session.user.id, clientId, reason, detail, now)
    .run();

  // Redaction: the free-text detail may contain PII, so only the enum reason
  // is recorded in the audit metadata.
  try {
    await recordAudit(
      c.env,
      {
        eventType: "oauth_client.reported",
        outcome: "success",
        actorUserId: session.user.id,
        subjectId: id,
        clientId,
        metadata: { reason },
      },
      c.executionCtx,
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "oauth_report_audit_failed",
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
  }

  return c.json({ reported: true }, 202);
});

/** Admin triage routes, mounted under /api/admin/oauth-reports. */
export const adminOauthReportRoutes = new Hono<AppEnv>();

adminOauthReportRoutes.get("/", async (c) => {
  // admin/bootadmin only: clients.manage_all is not held by developers.
  const gate = await requireAdminPermission(c, "clients.manage_all");
  if (!gate.ok) return gate.response;

  const statusFilter = c.req.query("status");
  if (statusFilter !== undefined && statusFilter !== "open" && statusFilter !== "resolved") {
    return c.json({ error: "invalid_status" }, 400);
  }

  const cursorParam = c.req.query("cursor");
  let cursor: { createdAt: string; id: string } | null = null;
  if (cursorParam !== undefined) {
    cursor = decodeCursor(cursorParam);
    if (!cursor) {
      return c.json({ error: "invalid_cursor" }, 400);
    }
  }

  const conditions: string[] = [];
  const bindings: (string | number)[] = [];
  if (statusFilter) {
    conditions.push("status = ?");
    bindings.push(statusFilter);
  }
  if (cursor) {
    conditions.push("(created_at < ? OR (created_at = ? AND id < ?))");
    bindings.push(cursor.createdAt, cursor.createdAt, cursor.id);
  }
  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  bindings.push(REPORTS_PER_PAGE + 1);

  const result = await c.env.PG72_ID_DB.prepare(
    `SELECT id, reporter_user_id, client_id, reason, detail, status,
            created_at, resolved_at, resolved_by_user_id
       FROM oauth_client_report
       ${where}
      ORDER BY created_at DESC, id DESC
      LIMIT ?`,
  )
    .bind(...bindings)
    .all<ReportRow>();

  const rows = result.results;
  const hasMore = rows.length > REPORTS_PER_PAGE;
  const page = hasMore ? rows.slice(0, REPORTS_PER_PAGE) : rows;
  const last = page.at(-1);

  return c.json({
    reports: page.map((row) => ({
      id: row.id,
      clientId: row.client_id,
      reason: row.reason,
      detail: row.detail,
      status: row.status,
      createdAt: row.created_at,
      resolvedAt: row.resolved_at,
    })),
    ...(hasMore && last
      ? { nextCursor: encodeCursor(last.created_at, last.id) }
      : {}),
  });
});

adminOauthReportRoutes.post("/:id/resolve", async (c) => {
  const gate = await requireAdminPermission(c, "clients.manage_all");
  if (!gate.ok) return gate.response;

  const id = c.req.param("id");
  if (!isUuid(id)) {
    return c.json({ error: "invalid_request" }, 400);
  }

  const now = new Date().toISOString();
  const event = createAuditEvent({
    eventType: "oauth_client.report_resolved",
    outcome: "success",
    actorUserId: gate.actor.userId,
    subjectId: id,
  });
  const results = await c.env.PG72_ID_DB.batch([
    auditInsertForOpenOAuthReportStatement(c.env, event, {
      actor: gate.actor.commitGuard,
      reportId: id,
    }),
    c.env.PG72_ID_DB.prepare(
      `UPDATE oauth_client_report
          SET status = 'resolved', resolved_at = ?, resolved_by_user_id = ?
        WHERE id = ?
          AND status = 'open'
          AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
    ).bind(now, gate.actor.userId, id, event.eventId),
  ]);
  if (
    !auditEventMutationCommitted(results[0]) ||
    results[1]?.meta.changes !== 1
  ) {
    return c.json({ error: "management_state_changed" }, 409);
  }
  await enqueueSecurityEvent(c.env, event, c.executionCtx);

  return c.json({ resolved: true, id, at: now });
});
