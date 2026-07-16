import {
  recordAudit,
  type AuditMetadata,
  type WaitUntilContext,
} from "./audit";

/** Audit event type for a successful sign-in (any provider or passkey). */
export const LOGIN_SUCCEEDED_EVENT = "user.login_succeeded";

/**
 * Self-service security-activity feed allow-list.
 *
 * Maps every event type a user may see about their own account to a stable,
 * PII-free summary label. The feed query filters `audit_event.subject_id` to
 * the signed-in user and to these types, so every producer of these events
 * must set `subject_id` to the affected user's id.
 */
export const SELF_ACTIVITY_SUMMARIES: Readonly<Record<string, string>> = {
  "user.login_succeeded": "登入成功",
  "passkey.registered": "新增 Passkey",
  "passkey.renamed": "重新命名 Passkey",
  "passkey.deleted": "移除 Passkey",
  "passkey.delete_blocked": "拒絕移除最後的登入方式",
  "passkey.step_up_succeeded": "Passkey 驗證成功",
  "passkey.step_up_failed": "Passkey 驗證失敗",
  "session.revoked": "登出單一裝置",
  "session.revoked_others": "登出其他裝置",
  "session.revoked_all": "登出所有裝置",
  "user.sessions_revoked": "管理員撤銷你的登入工作階段",
  "user.suspended": "帳號被停權",
  "user.reactivated": "帳號恢復啟用",
  "oauth.consent_granted": "授權應用程式",
  "oauth.consent_revoked": "撤銷應用程式授權",
  "account.linked": "連結登入方式",
  "account.unlinked": "解除登入方式連結",
  "user.profile_updated": "更新個人資料",
  "user.avatar_updated": "更新頭貼",
  "user.role_changed": "平台角色變更",
};

export const SELF_ACTIVITY_EVENT_TYPES: readonly string[] = Object.keys(
  SELF_ACTIVITY_SUMMARIES,
);

/**
 * Better Auth database-hook context. Only the fields we read defensively are
 * declared; everything is optional because the hook can also run without a
 * request (programmatic session creation).
 */
export interface AuthHookContext {
  path?: string;
  params?: Record<string, string | undefined>;
  request?: { headers?: Headers };
  headers?: Headers;
}

function headerFromContext(
  context: AuthHookContext | undefined,
  name: string,
): string | null {
  const fromRequest = context?.request?.headers?.get?.(name);
  if (typeof fromRequest === "string") return fromRequest;
  const fromHeaders = context?.headers?.get?.(name);
  return typeof fromHeaders === "string" ? fromHeaders : null;
}

/**
 * Resolves the login provider from the request path, mirroring Better Auth's
 * own last-login-method resolver: social callbacks carry the provider id, the
 * passkey ceremony is fixed.
 */
export function providerFromAuthContext(
  context: AuthHookContext | undefined,
): string | null {
  const path = typeof context?.path === "string" ? context.path : "";
  if (path.startsWith("/callback/") || path.startsWith("/oauth2/callback/")) {
    return context?.params?.id ?? path.split("/").pop() ?? null;
  }
  if (path.includes("/passkey/verify-authentication")) return "passkey";
  return null;
}

/** Coarse device class from a User-Agent; never stores the raw string. */
export function deviceTypeFromUserAgent(userAgent: string | null): string {
  if (!userAgent) return "unknown";
  const value = userAgent.toLowerCase();
  if (/bot|crawler|spider|curl|wget|python-requests|headless/.test(value)) {
    return "bot";
  }
  if (/ipad|tablet/.test(value)) return "tablet";
  if (/mobi|iphone|android/.test(value)) return "mobile";
  return "desktop";
}

/** Masks an IP to a coarse prefix so the audit trail never stores a full IP. */
export function maskIp(ip: string | null): string | null {
  if (!ip) return null;
  if (ip === "local") return "local";
  if (ip.includes(":")) {
    const head = ip.split(":")[0];
    return head ? `${head}::` : null;
  }
  const parts = ip.split(".");
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.x.x`;
  return null;
}

/**
 * Records a successful sign-in with a redacted source summary (provider,
 * coarse device class, masked IP prefix). Never throws into the auth flow.
 */
export async function recordLoginAudit(
  env: Env,
  userId: string,
  context: AuthHookContext | undefined,
  executionCtx?: WaitUntilContext,
): Promise<void> {
  try {
    const metadata: AuditMetadata = {
      provider: providerFromAuthContext(context) ?? "unknown",
      device: deviceTypeFromUserAgent(headerFromContext(context, "user-agent")),
    };
    const maskedIp = maskIp(headerFromContext(context, "cf-connecting-ip"));
    if (maskedIp) metadata.ipPrefix = maskedIp;

    await recordAudit(
      env,
      {
        eventType: LOGIN_SUCCEEDED_EVENT,
        outcome: "success",
        subjectId: userId,
        metadata,
      },
      executionCtx,
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "login_audit_failed",
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
  }
}

/**
 * Auth handler paths that produce a self security-activity event once the
 * underlying Better Auth call succeeds.
 */
export const ACTIVITY_AUDIT_PATHS: ReadonlySet<string> = new Set([
  "/revoke-session",
  "/revoke-sessions",
  "/revoke-other-sessions",
  "/oauth2/consent",
  "/passkey/verify-registration",
]);

const SESSION_REVOKE_EVENTS: Readonly<Record<string, string>> = {
  "/revoke-session": "session.revoked",
  "/revoke-sessions": "session.revoked_all",
  "/revoke-other-sessions": "session.revoked_others",
};

export interface ConsentActivity {
  accept: boolean;
  clientId: string | null;
}

/**
 * Reads the consent decision (accept flag and client id) from a cloned request
 * before the auth handler consumes the body. The client id is taken from the
 * plaintext `oauth_query` string for the audit metadata only; the provider
 * still re-verifies the signed query, so a tampered id cannot cause a grant.
 */
export async function parseConsentActivity(
  request: Request,
): Promise<ConsentActivity | null> {
  // Read a clone so the original body is left intact for the auth handler.
  const clone = request.clone();
  const contentType = clone.headers.get("content-type")?.toLowerCase() ?? "";
  const clientIdFrom = (oauthQuery: unknown): string | null =>
    typeof oauthQuery === "string"
      ? new URLSearchParams(oauthQuery).get("client_id")
      : null;
  try {
    if (contentType.startsWith("application/json")) {
      const body = (await clone.json()) as {
        accept?: unknown;
        oauth_query?: unknown;
      };
      return { accept: body.accept === true, clientId: clientIdFrom(body.oauth_query) };
    }
    if (
      contentType.startsWith("application/x-www-form-urlencoded") ||
      contentType.startsWith("multipart/form-data")
    ) {
      const form = await clone.formData();
      const accept = form.get("accept");
      return {
        accept: accept === "true" || accept === "1",
        clientId: clientIdFrom(form.get("oauth_query")),
      };
    }
  } catch {
    return null;
  }
  return null;
}

async function consentWasGranted(response: Response): Promise<boolean> {
  try {
    const clone = response.clone();
    if (
      !clone.headers.get("content-type")?.toLowerCase().startsWith("application/json")
    ) {
      return false;
    }
    const body = (await clone.json()) as { redirect?: boolean; url?: string };
    if (body.redirect !== true || typeof body.url !== "string") return false;
    return new URL(body.url).searchParams.has("code");
  } catch {
    return false;
  }
}

/**
 * Writes the self security-activity event for a completed auth-handler call.
 * The caller supplies the pre-request session user id (session revocation can
 * invalidate the current session, so it cannot be read afterwards) and, for
 * consent, the parsed decision.
 */
export async function recordAuthPathActivity(
  env: Env,
  pathname: string,
  response: Response,
  userId: string,
  consent: ConsentActivity | null,
  executionCtx?: WaitUntilContext,
): Promise<void> {
  if (!response.ok) return;
  try {
    const revokeEvent = SESSION_REVOKE_EVENTS[pathname];
    if (revokeEvent) {
      await recordAudit(
        env,
        { eventType: revokeEvent, outcome: "success", subjectId: userId },
        executionCtx,
      );
      return;
    }
    if (pathname === "/passkey/verify-registration") {
      await recordAudit(
        env,
        { eventType: "passkey.registered", outcome: "success", subjectId: userId },
        executionCtx,
      );
      return;
    }
    if (
      pathname === "/oauth2/consent" &&
      consent?.accept &&
      (await consentWasGranted(response))
    ) {
      await recordAudit(
        env,
        {
          eventType: "oauth.consent_granted",
          outcome: "success",
          subjectId: userId,
          clientId: consent.clientId ?? undefined,
        },
        executionCtx,
      );
    }
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "auth_activity_audit_failed",
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
  }
}

/** Opaque keyset cursor over (occurred_at, id) for the activity feed. */
export function encodeActivityCursor(occurredAt: string, id: string): string {
  return btoa(`${occurredAt}|${id}`)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export function decodeActivityCursor(
  cursor: string,
): { occurredAt: string; id: string } | null {
  if (cursor.length > 256 || !/^[A-Za-z0-9_-]+$/.test(cursor)) return null;
  try {
    const decoded = atob(cursor.replaceAll("-", "+").replaceAll("_", "/"));
    const separator = decoded.indexOf("|");
    if (separator <= 0) return null;
    const occurredAt = decoded.slice(0, separator);
    const id = decoded.slice(separator + 1);
    if (!occurredAt || !id) return null;
    return { occurredAt, id };
  } catch {
    return null;
  }
}

export function summaryForEvent(eventType: string): string {
  return SELF_ACTIVITY_SUMMARIES[eventType] ?? eventType;
}

export function providerFromMetadata(
  metadataJson: string | null,
): string | undefined {
  if (!metadataJson) return undefined;
  try {
    const parsed = JSON.parse(metadataJson) as Record<string, unknown>;
    return typeof parsed.provider === "string" ? parsed.provider : undefined;
  } catch {
    return undefined;
  }
}
