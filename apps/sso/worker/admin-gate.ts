import type { Context } from "hono";

import {
  accountAccessLevel,
  recordRestrictedActionDenied,
} from "./account-access";
import { createAuth } from "./auth";
import {
  FRESH_SESSION_MAX_AGE_MS,
  readRuntimeConfig,
} from "./config";
import { readPasskeyStepUpState } from "./passkey-step-up";
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
  options: { fresh?: boolean; passkeyStepUp?: boolean } = {},
): Promise<AdminGate> {
  const auth = createAuth(c.env, c.executionCtx);
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) {
    return { ok: false, response: c.json({ error: "unauthorized" }, 401) };
  }

  const config = readRuntimeConfig(c.env);
  const currentUser = await c.env.PG72_ID_DB.prepare(
    `SELECT email, role, status, accessLevel
       FROM user
      WHERE id = ?
      LIMIT 1`,
  )
    .bind(session.user.id)
    .first<{
      accessLevel: unknown;
      email: string;
      role: string | null;
      status: string;
    }>();
  if (!currentUser || currentUser.status !== "active") {
    return { ok: false, response: c.json({ error: "forbidden" }, 403) };
  }

  const accessLevel = accountAccessLevel(currentUser.accessLevel);
  const role = effectivePlatformRole(
    currentUser.role,
    currentUser.email,
    config,
    accessLevel,
  );
  const rateLimit = await c.env.ADMIN_RATE_LIMITER.limit({
    key: session.user.id,
  });
  if (!rateLimit.success) {
    return { ok: false, response: c.json({ error: "rate_limited" }, 429) };
  }

  if (accessLevel === "restricted") {
    try {
      await recordRestrictedActionDenied(
        c.env,
        session.user.id,
        permission,
        c.executionCtx,
      );
    } catch (error) {
      console.error(
        JSON.stringify({
          event: "restricted_action_audit_failed",
          error: error instanceof Error ? error.name : "UnknownError",
        }),
      );
    }
    return { ok: false, response: c.json({ error: "forbidden" }, 403) };
  }
  if (!hasPermission(role, permission)) {
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
  if (options.passkeyStepUp) {
    const stepUp = await readPasskeyStepUpState(
      c.env,
      session.session.id,
      session.user.id,
      config.passkeyStepUpMaxAgeMs,
    );
    if (!stepUp) {
      return { ok: false, response: c.json({ error: "unauthorized" }, 401) };
    }
    if (!stepUp.hasPasskey) {
      return {
        ok: false,
        response: c.json(
          {
            code: "PASSKEY_ENROLLMENT_REQUIRED",
            error: "passkey_enrollment_required",
          },
          403,
        ),
      };
    }
    if (!stepUp.verified) {
      return {
        ok: false,
        response: c.json(
          {
            code: "PASSKEY_STEP_UP_REQUIRED",
            error: "passkey_step_up_required",
          },
          403,
        ),
      };
    }
  }

  return { ok: true, actor: { role, userId: session.user.id } };
}
