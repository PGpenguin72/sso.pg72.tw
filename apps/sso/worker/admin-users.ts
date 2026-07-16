import { Hono, type Context } from "hono";

import type { AccountAccessLevel } from "./account-access";
import { requireAdminPermission, type AdminActor } from "./admin-gate";
import {
  auditInsertForExistingUserStatement,
  createAuditEvent,
  enqueueSecurityEvent,
  recordAudit,
  type AuditMetadata,
  type AuditOutcome,
  type ExistingUserAuditGuard,
} from "./audit";
import { ownedClientShutdownStatements } from "./client-ownership";
import { readRuntimeConfig } from "./config";
import {
  denyRoleChange,
  denyUserManagement,
  effectivePlatformRole,
  isPlatformRole,
  type AdminActionDenial,
  type PlatformRole,
} from "./roles";

type AppEnv = { Bindings: Env };

const USERS_PER_PAGE_DEFAULT = 20;
const USERS_PER_PAGE_MAX = 50;
const USERS_PAGE_MAX = 10_000;
const USER_QUERY_MAX_LENGTH = 254;

interface RoleInput {
  role?: unknown;
}

interface StatusInput {
  suspended?: unknown;
}

interface AccessInput {
  restricted?: unknown;
}

interface AdminUserRow {
  id: string;
  name: string | null;
  email: string;
  role: string | null;
  status: string;
  accessLevel: AccountAccessLevel;
  createdAt: string;
  lastSessionAt: string | null;
  passkeyCount: number;
  authorizedAppCount: number;
}

interface TargetUserRow {
  id: string;
  email: string;
  role: string | null;
  status: string;
  accessLevel: AccountAccessLevel;
}

interface CountRow {
  total: number;
}

function validUserId(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  );
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

async function auditUserAdmin(
  c: Context<AppEnv>,
  input: {
    eventType: string;
    outcome: AuditOutcome;
    actorUserId: string;
    subjectId?: string;
    metadata?: AuditMetadata;
  },
): Promise<void> {
  try {
    await recordAudit(c.env, input, c.executionCtx);
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "user_admin_audit_failed",
        eventType: input.eventType,
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
  }
}

interface ResolvedTarget {
  effectiveRole: PlatformRole;
  protected: boolean;
  row: TargetUserRow;
}

async function fetchTarget(
  c: Context<AppEnv>,
  userId: string,
): Promise<ResolvedTarget | null> {
  const row = await c.env.PG72_ID_DB.prepare(
    "SELECT id, email, role, status, accessLevel FROM user WHERE id = ? LIMIT 1",
  )
    .bind(userId)
    .first<TargetUserRow>();
  if (!row) return null;

  const config = readRuntimeConfig(c.env);
  const effectiveRole = effectivePlatformRole(row.role, row.email, config);
  return {
    effectiveRole,
    // A stale stored 'bootadmin' row also stays protected here: the DB
    // demote/delete guards would reject the write anyway, so surface a
    // clear denial instead of a 500.
    protected: effectiveRole === "bootadmin" || row.role === "bootadmin",
    row,
  };
}

function denialResponse(
  c: Context<AppEnv>,
  denial: AdminActionDenial,
): Response {
  if (denial === "cannot_modify_self") {
    return c.json({ error: "cannot_modify_self" }, 409);
  }
  return c.json({ error: denial }, 403);
}

async function deniedRoleChange(
  c: Context<AppEnv>,
  actor: AdminActor,
  target: ResolvedTarget,
  nextRole: PlatformRole,
  via: "admin" | "invitation",
): Promise<AdminActionDenial | null> {
  const denial = denyRoleChange({
    actorRole: actor.role,
    actorUserId: actor.userId,
    nextRole,
    targetProtected: target.protected,
    targetRole: target.effectiveRole,
    targetUserId: target.row.id,
  });
  const restrictedDenial =
    target.row.accessLevel === "restricted" && nextRole !== "user"
      ? "restricted_account"
      : null;
  const finalDenial = denial ?? restrictedDenial;
  if (finalDenial && finalDenial !== "cannot_modify_self") {
    await auditUserAdmin(c, {
      eventType: "user.role_changed",
      outcome: "denied",
      actorUserId: actor.userId,
      subjectId: target.row.id,
      metadata: { reason: finalDenial, to: nextRole, via },
    });
  }
  return finalDenial;
}

function transitionGuard(target: ResolvedTarget): ExistingUserAuditGuard {
  return {
    expectedAccessLevel: target.row.accessLevel,
    expectedRole: target.row.role,
    expectedStatus: target.row.status,
    userId: target.row.id,
  };
}

function guardedUserTransitionUpdate(
  c: Context<AppEnv>,
  eventId: string,
  target: ResolvedTarget,
  next: {
    accessLevel: AccountAccessLevel;
    role: string | null;
    status: string;
    updatedAt: string;
  },
): D1PreparedStatement {
  return c.env.PG72_ID_DB.prepare(
    `UPDATE user
        SET accessLevel = ?, role = ?, status = ?, updatedAt = ?
      WHERE id = ?
        AND accessLevel = ?
        AND role IS ?
        AND status = ?
        AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
  ).bind(
    next.accessLevel,
    next.role,
    next.status,
    next.updatedAt,
    target.row.id,
    target.row.accessLevel,
    target.row.role,
    target.row.status,
    eventId,
  );
}

function guardedUserStatement(
  c: Context<AppEnv>,
  eventId: string,
  sql: string,
  ...bindings: unknown[]
): D1PreparedStatement {
  return c.env.PG72_ID_DB.prepare(
    `${sql} AND EXISTS (SELECT 1 FROM audit_event WHERE id = ?)`,
  ).bind(...bindings, eventId);
}

/**
 * Applies a validated role change and writes the audit trail. Callers must
 * have already passed deniedRoleChange.
 */
async function applyRoleChange(
  c: Context<AppEnv>,
  actor: AdminActor,
  target: ResolvedTarget,
  nextRole: PlatformRole,
  via: "admin" | "invitation",
): Promise<string> {
  const now = new Date().toISOString();
  await c.env.PG72_ID_DB.prepare(
    "UPDATE user SET role = ?, updatedAt = ? WHERE id = ?",
  )
    .bind(nextRole, now, target.row.id)
    .run();

  await auditUserAdmin(c, {
    eventType: "user.role_changed",
    outcome: "success",
    actorUserId: actor.userId,
    subjectId: target.row.id,
    metadata: { from: target.effectiveRole, to: nextRole, via },
  });
  return now;
}

export const adminUserRoutes = new Hono<AppEnv>();

// Offset pagination: the invite-only user base stays small (well under the
// D1 scan budget), the query is fully indexable by rowid order, and offset
// keeps stable page links for the UI. Revisit keyset pagination only if the
// directory ever grows past tens of thousands of rows.
adminUserRoutes.get("/", async (c) => {
  const gate = await requireAdminPermission(c, "users.read");
  if (!gate.ok) return gate.response;

  const query = (c.req.query("q") ?? "").trim();
  const access = c.req.query("access") ?? "all";
  const page = Number.parseInt(c.req.query("page") ?? "1", 10);
  const perPage = Number.parseInt(
    c.req.query("perPage") ?? String(USERS_PER_PAGE_DEFAULT),
    10,
  );
  if (
    query.length > USER_QUERY_MAX_LENGTH ||
    (access !== "all" && access !== "standard" && access !== "restricted") ||
    !Number.isInteger(page) ||
    page < 1 ||
    page > USERS_PAGE_MAX ||
    !Number.isInteger(perPage) ||
    perPage < 1 ||
    perPage > USERS_PER_PAGE_MAX
  ) {
    return c.json({ error: "invalid_request" }, 400);
  }

  const like = `%${query.replaceAll(/[\\%_]/g, (char) => `\\${char}`)}%`;
  const filter = `WHERE (?1 = ''
        OR u.email LIKE ?2 ESCAPE '\\'
        OR u.name LIKE ?2 ESCAPE '\\')
      AND (?3 = 'all' OR u.accessLevel = ?3)`;

  const [listing, count] = await Promise.all([
    c.env.PG72_ID_DB.prepare(
      `SELECT u.id, u.name, u.email, u.role, u.status, u.accessLevel, u.createdAt,
              (SELECT MAX(s.updatedAt) FROM session s
                WHERE s.userId = u.id) AS lastSessionAt,
              (SELECT COUNT(*) FROM passkey p
                WHERE p.userId = u.id) AS passkeyCount,
              (SELECT COUNT(DISTINCT oc.clientId) FROM oauthConsent oc
                WHERE oc.userId = u.id) AS authorizedAppCount
         FROM user u
        ${filter}
        ORDER BY u.createdAt DESC, u.id ASC
        LIMIT ?4 OFFSET ?5`,
    )
      .bind(query, like, access, perPage, (page - 1) * perPage)
      .all<AdminUserRow>(),
    c.env.PG72_ID_DB.prepare(
      `SELECT COUNT(*) AS total FROM user u ${filter}`,
    )
      .bind(query, like, access)
      .first<CountRow>(),
  ]);

  const config = readRuntimeConfig(c.env);

  // codex.md §14 requires auditing administrator data queries. The search
  // text is intentionally not recorded: it may contain an email address.
  await auditUserAdmin(c, {
    eventType: "admin.users_listed",
    outcome: "success",
    actorUserId: gate.actor.userId,
    metadata: {
      accessFilter: access,
      filtered: query.length > 0 || access !== "all",
      page,
    },
  });

  return c.json({
    page,
    perPage,
    total: count?.total ?? 0,
    viewerRole: gate.actor.role,
    users: listing.results.map((row) => ({
      id: row.id,
      name: row.name ?? "",
      email: row.email,
      role: effectivePlatformRole(row.role, row.email, config),
      status: row.status,
      accessLevel: row.accessLevel,
      createdAt: row.createdAt,
      lastSessionAt: row.lastSessionAt,
      passkeyCount: row.passkeyCount,
      authorizedAppCount: row.authorizedAppCount,
    })),
  });
});

adminUserRoutes.post("/:userId/role", async (c) => {
  const gate = await requireAdminPermission(c, "users.assign_roles");
  if (!gate.ok) return gate.response;

  const userId = c.req.param("userId");
  const input = await readJson<RoleInput>(c.req.raw);
  if (!validUserId(userId)) {
    return c.json({ error: "invalid_request" }, 400);
  }
  if (!isPlatformRole(input?.role) || input.role === "bootadmin") {
    return c.json({ error: "invalid_role" }, 400);
  }

  const target = await fetchTarget(c, userId);
  if (!target) {
    return c.json({ error: "user_not_found" }, 404);
  }

  const denial = await deniedRoleChange(c, gate.actor, target, input.role, "admin");
  if (denial) return denialResponse(c, denial);

  const at = await applyRoleChange(c, gate.actor, target, input.role, "admin");
  return c.json({ userId, role: input.role, at });
});

adminUserRoutes.post("/:userId/status", async (c) => {
  const gate = await requireAdminPermission(c, "users.manage");
  if (!gate.ok) return gate.response;

  const userId = c.req.param("userId");
  const input = await readJson<StatusInput>(c.req.raw);
  if (!validUserId(userId) || typeof input?.suspended !== "boolean") {
    return c.json({ error: "invalid_request" }, 400);
  }

  const target = await fetchTarget(c, userId);
  if (!target) {
    return c.json({ error: "user_not_found" }, 404);
  }
  const denial = denyUserManagement({
    actorUserId: gate.actor.userId,
    targetProtected: target.protected,
    targetUserId: userId,
  });
  if (denial === "bootadmin_protected") {
    await auditUserAdmin(c, {
      eventType: input.suspended ? "user.suspended" : "user.reactivated",
      outcome: "denied",
      actorUserId: gate.actor.userId,
      subjectId: userId,
      metadata: { reason: denial },
    });
    return denialResponse(c, denial);
  }
  if (denial === "cannot_modify_self" && input.suspended) {
    return c.json({ error: "cannot_suspend_self" }, 409);
  }
  if (denial) return denialResponse(c, denial);

  const now = new Date().toISOString();
  const event = createAuditEvent({
    eventType: input.suspended ? "user.suspended" : "user.reactivated",
    outcome: "success",
    actorUserId: gate.actor.userId,
    subjectId: userId,
    metadata: { accessLevel: target.row.accessLevel },
  });
  const statements = [
    auditInsertForExistingUserStatement(c.env, event, transitionGuard(target)),
    guardedUserTransitionUpdate(c, event.eventId, target, {
      accessLevel: target.row.accessLevel,
      role: target.row.role,
      status: input.suspended ? "suspended" : "active",
      updatedAt: now,
    }),
  ];

  if (input.suspended) {
    statements.push(
      guardedUserStatement(
        c,
        event.eventId,
        "DELETE FROM session WHERE userId = ?",
        userId,
      ),
      guardedUserStatement(
        c,
        event.eventId,
        "UPDATE oauthRefreshToken SET revoked = ? WHERE userId = ? AND revoked IS NULL",
        now,
        userId,
      ),
      guardedUserStatement(
        c,
        event.eventId,
        "DELETE FROM oauthAccessToken WHERE userId = ?",
        userId,
      ),
    );
  }

  const results = await c.env.PG72_ID_DB.batch(statements);
  if (results[0]?.meta.changes !== 1 || results[1]?.meta.changes !== 1) {
    return c.json({ error: "user_state_changed" }, 409);
  }
  await enqueueSecurityEvent(c.env, event, c.executionCtx);

  return c.json({
    userId,
    status: input.suspended ? "suspended" : "active",
    accessLevel: target.row.accessLevel,
    at: now,
  });
});

adminUserRoutes.post("/:userId/access", async (c) => {
  const gate = await requireAdminPermission(c, "users.manage");
  if (!gate.ok) return gate.response;

  const userId = c.req.param("userId");
  const input = await readJson<AccessInput>(c.req.raw);
  if (!validUserId(userId) || typeof input?.restricted !== "boolean") {
    return c.json({ error: "invalid_request" }, 400);
  }

  const target = await fetchTarget(c, userId);
  if (!target) return c.json({ error: "user_not_found" }, 404);
  let denial = denyUserManagement({
    actorUserId: gate.actor.userId,
    targetProtected: target.protected,
    targetUserId: userId,
  });
  if (!denial && input.restricted && target.effectiveRole !== "user") {
    denial = denyRoleChange({
      actorRole: gate.actor.role,
      actorUserId: gate.actor.userId,
      nextRole: "user",
      targetProtected: target.protected,
      targetRole: target.effectiveRole,
      targetUserId: userId,
    });
  }
  const eventType = input.restricted
    ? "user.access_restricted"
    : "user.access_promoted";
  if (denial) {
    await auditUserAdmin(c, {
      eventType,
      outcome: "denied",
      actorUserId: gate.actor.userId,
      subjectId: userId,
      metadata: { reason: denial },
    });
    return denialResponse(c, denial);
  }

  const nextAccessLevel: AccountAccessLevel = input.restricted
    ? "restricted"
    : "standard";
  const nextRole = input.restricted ? "user" : target.row.role;
  const now = new Date().toISOString();
  const event = createAuditEvent({
    eventType,
    outcome: "success",
    actorUserId: gate.actor.userId,
    subjectId: userId,
    metadata: {
      from: target.row.accessLevel,
      previousRole: target.effectiveRole,
      to: nextAccessLevel,
    },
  });
  const statements = [
    auditInsertForExistingUserStatement(c.env, event, transitionGuard(target)),
    guardedUserTransitionUpdate(c, event.eventId, target, {
      accessLevel: nextAccessLevel,
      role: nextRole,
      status: target.row.status,
      updatedAt: now,
    }),
  ];
  if (input.restricted) {
    statements.push(
      guardedUserStatement(
        c,
        event.eventId,
        "DELETE FROM session WHERE userId = ?",
        userId,
      ),
      guardedUserStatement(
        c,
        event.eventId,
        "UPDATE oauthRefreshToken SET revoked = ? WHERE userId = ? AND revoked IS NULL",
        now,
        userId,
      ),
      guardedUserStatement(
        c,
        event.eventId,
        "DELETE FROM oauthAccessToken WHERE userId = ?",
        userId,
      ),
    );
  }

  const results = await c.env.PG72_ID_DB.batch(statements);
  if (results[0]?.meta.changes !== 1 || results[1]?.meta.changes !== 1) {
    return c.json({ error: "user_state_changed" }, 409);
  }
  await enqueueSecurityEvent(c.env, event, c.executionCtx);

  return c.json({
    userId,
    accessLevel: nextAccessLevel,
    role: nextRole ?? "user",
    status: target.row.status,
    at: now,
  });
});

adminUserRoutes.post("/:userId/revoke-sessions", async (c) => {
  const gate = await requireAdminPermission(c, "users.manage");
  if (!gate.ok) return gate.response;

  const userId = c.req.param("userId");
  if (!validUserId(userId)) {
    return c.json({ error: "invalid_request" }, 400);
  }

  const target = await fetchTarget(c, userId);
  if (!target) {
    return c.json({ error: "user_not_found" }, 404);
  }
  const denial = denyUserManagement({
    actorUserId: gate.actor.userId,
    targetProtected: target.protected,
    targetUserId: userId,
  });
  if (denial === "bootadmin_protected") {
    await auditUserAdmin(c, {
      eventType: "user.sessions_revoked",
      outcome: "denied",
      actorUserId: gate.actor.userId,
      subjectId: userId,
      metadata: { reason: denial },
    });
  }
  if (denial) return denialResponse(c, denial);

  const deletion = await c.env.PG72_ID_DB.prepare(
    "DELETE FROM session WHERE userId = ?",
  )
    .bind(userId)
    .run();

  await auditUserAdmin(c, {
    eventType: "user.sessions_revoked",
    outcome: "success",
    actorUserId: gate.actor.userId,
    subjectId: userId,
    metadata: { sessions: deletion.meta.changes },
  });

  return c.json({ userId, revokedSessions: deletion.meta.changes });
});

adminUserRoutes.delete("/:userId", async (c) => {
  const gate = await requireAdminPermission(c, "users.manage");
  if (!gate.ok) return gate.response;

  const userId = c.req.param("userId");
  if (!validUserId(userId)) {
    return c.json({ error: "invalid_request" }, 400);
  }

  const target = await fetchTarget(c, userId);
  if (!target) {
    return c.json({ error: "user_not_found" }, 404);
  }
  const denial = denyUserManagement({
    actorUserId: gate.actor.userId,
    targetProtected: target.protected,
    targetUserId: userId,
  });
  if (denial === "bootadmin_protected") {
    await auditUserAdmin(c, {
      eventType: "user.deleted",
      outcome: "denied",
      actorUserId: gate.actor.userId,
      subjectId: userId,
      metadata: { reason: denial },
    });
  }
  if (denial) return denialResponse(c, denial);

  const now = new Date().toISOString();
  // Owned OAuth clients are disabled and orphaned first; sessions,
  // accounts, passkeys, tokens, and consents cascade with the user row.
  // Pending authorization codes live in the verification table and are
  // purged explicitly.
  const results = await c.env.PG72_ID_DB.batch([
    ...ownedClientShutdownStatements(c.env, userId, now),
    c.env.PG72_ID_DB.prepare(
      `DELETE FROM verification
        WHERE CASE WHEN json_valid(value) THEN
          json_extract(value, '$.type') = 'authorization_code'
          AND json_extract(value, '$.userId') = ?
        ELSE 0 END`,
    ).bind(userId),
    c.env.PG72_ID_DB.prepare("DELETE FROM user WHERE id = ?").bind(userId),
  ]);
  // meta.changes includes cascaded rows, so only zero means missing.
  if (!results.at(-1)?.meta.changes) {
    return c.json({ error: "user_not_found" }, 404);
  }

  await auditUserAdmin(c, {
    eventType: "user.deleted",
    outcome: "success",
    actorUserId: gate.actor.userId,
    subjectId: userId,
    metadata: { via: "admin" },
  });

  return c.json({ deleted: true, userId });
});

export {
  applyRoleChange,
  deniedRoleChange,
  fetchTarget,
  readJson,
  validUserId,
};
