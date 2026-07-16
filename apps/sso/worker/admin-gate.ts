import type { Context } from "hono";

import { createAuth } from "./auth";
import {
  FRESH_SESSION_MAX_AGE_MS,
  readRuntimeConfig,
} from "./config";
import {
  effectivePlatformRole,
  hasPermission,
  type AdminPermission,
  type PlatformRole,
} from "./roles";

type AppEnv = { Bindings: Env };

export interface AdminActor {
  role: PlatformRole;
  userId: string;
}

export type AdminGate =
  | { ok: true; actor: AdminActor }
  | { ok: false; response: Response };

/**
 * Shared guard for /api/admin routes: active session, effective platform
 * role holding the required permission, and the admin rate limit. Exact
 * Origin and body-size checks are enforced by the /api/admin/* middleware.
 */
export async function requireAdminPermission(
  c: Context<AppEnv>,
  permission: AdminPermission,
  options: { fresh?: boolean } = {},
): Promise<AdminGate> {
  const auth = createAuth(c.env, c.executionCtx);
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) {
    return { ok: false, response: c.json({ error: "unauthorized" }, 401) };
  }

  const config = readRuntimeConfig(c.env);
  const role = effectivePlatformRole(
    session.user.role,
    session.user.email,
    config,
  );
  if (session.user.status !== "active" || !hasPermission(role, permission)) {
    return { ok: false, response: c.json({ error: "forbidden" }, 403) };
  }
  if (options.fresh) {
    const createdAt = new Date(session.session.createdAt).getTime();
    const sessionAgeMs = Date.now() - createdAt;
    const sessionIsFresh =
      Number.isFinite(createdAt) &&
      sessionAgeMs >= 0 &&
      sessionAgeMs < FRESH_SESSION_MAX_AGE_MS;
    if (!sessionIsFresh) {
      return {
        ok: false,
        response: c.json(
          {
            code: "SESSION_NOT_FRESH",
            error: "fresh_session_required",
          },
          403,
        ),
      };
    }
  }

  const rateLimit = await c.env.ADMIN_RATE_LIMITER.limit({
    key: session.user.id,
  });
  if (!rateLimit.success) {
    return { ok: false, response: c.json({ error: "rate_limited" }, 429) };
  }

  return { ok: true, actor: { role, userId: session.user.id } };
}
