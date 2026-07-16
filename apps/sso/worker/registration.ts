import { APIError } from "better-auth/api";

import { recordAudit, type WaitUntilContext } from "./audit";
import { normalizeEmail, type RuntimeConfig } from "./config";
import {
  claimPublicRegistrationIntent,
  type PublicRegistrationOAuthBinding,
} from "./public-registration";

interface InvitationRow {
  id: string;
  role: "admin" | "developer" | "user";
}

interface SessionUserRow {
  email: string;
  role: string | null;
  status: "active" | "suspended";
}

export interface RegistrationInput {
  email: string;
  emailVerified: boolean;
  /** Client IP taken from `cf-connecting-ip`; `"local"` when absent. */
  clientIp: string;
  providerId?: string;
  registrationBinding?: PublicRegistrationOAuthBinding;
}

export interface RegistrationGrant {
  legalAcceptedAt?: Date;
  privacyAcceptedVersion?: string;
  role: "bootadmin" | "admin" | "developer" | "user";
  status: "active";
  termsAcceptedVersion?: string;
}

/**
 * Gate for every new-account creation, in both `invite` and `public`
 * registration modes.
 *
 * Order matters for abuse resistance: the dedicated per-IP registration
 * rate limit (stricter than the sign-in limiter) is consumed before any
 * denial audit write or invitation lookup, so neither can be spammed
 * faster than the registration budget.
 */
export async function authorizeRegistration(
  env: Env,
  config: RuntimeConfig,
  input: RegistrationInput,
  executionCtx?: WaitUntilContext,
): Promise<RegistrationGrant> {
  const email = normalizeEmail(input.email);
  const isBootstrapAdmin = email === config.bootstrapAdminEmail;

  const rateLimit = await env.REGISTRATION_RATE_LIMITER.limit({
    key: input.clientIp,
  });
  if (!rateLimit.success) {
    await recordAudit(
      env,
      { eventType: "registration.rate_limited", outcome: "denied" },
      executionCtx,
    );
    throw new APIError("TOO_MANY_REQUESTS", {
      code: "REGISTRATION_RATE_LIMITED",
      message: "Too many registration attempts. Please try again later.",
    });
  }

  // Both modes require the upstream identity provider to assert a verified
  // email. The denial does not reveal whether any account already exists.
  if (!input.emailVerified) {
    await recordAudit(
      env,
      { eventType: "registration.denied", outcome: "denied" },
      executionCtx,
    );
    throw new APIError("FORBIDDEN", {
      code: "EMAIL_NOT_VERIFIED",
      message: "A verified email address is required to create a PGID account.",
    });
  }

  let legalAcceptance: Partial<RegistrationGrant> = {};
  if (config.registrationMode === "public") {
    if (input.providerId !== "google") {
      await recordAudit(
        env,
        { eventType: "registration.denied", outcome: "denied" },
        executionCtx,
      );
      throw new APIError("FORBIDDEN", {
        code: "REGISTRATION_PREREQUISITE_REQUIRED",
        message: "Complete registration verification before creating an account.",
      });
    }
    legalAcceptance = await claimPublicRegistrationIntent(
      env,
      config,
      input.registrationBinding,
      executionCtx,
    );
  }

  // Invitations stay functional in public mode: a pending invitation still
  // assigns its role and is consumed by the create.after hook.
  const invitation = await env.PG72_ID_DB.prepare(
    `SELECT id, role
       FROM invitation
      WHERE email_normalized = ?
        AND consumed_at IS NULL
        AND revoked_at IS NULL
        AND expires_at > ?
      LIMIT 1`,
  )
    .bind(email, new Date().toISOString())
    .first<InvitationRow>();

  if (config.registrationMode === "invite" && !invitation && !isBootstrapAdmin) {
    await recordAudit(
      env,
      { eventType: "registration.denied", outcome: "denied" },
      executionCtx,
    );
    throw new APIError("FORBIDDEN", {
      code: "INVITATION_REQUIRED",
      message: "This PGID account requires an invitation.",
    });
  }

  return {
    ...legalAcceptance,
    role: isBootstrapAdmin ? "bootadmin" : (invitation?.role ?? "user"),
    status: "active",
  };
}

/**
 * Session-creation guard shared by every login path (Google, Passkey).
 * Suspended accounts and dangling user IDs (deleted accounts) can never
 * mint a new session, regardless of the registration mode.
 */
export async function assertSessionUserActive(
  env: Env,
  config: RuntimeConfig,
  userId: string,
): Promise<void> {
  const user = await env.PG72_ID_DB.prepare(
    "SELECT email, role, status FROM user WHERE id = ? LIMIT 1",
  )
    .bind(userId)
    .first<SessionUserRow>();

  if (!user || user.status !== "active") {
    throw new APIError("FORBIDDEN", {
      code: "ACCOUNT_SUSPENDED",
      message: "This account is not allowed to create a session.",
    });
  }

  // Lazy data conversion for the four-tier role model: the bootstrap
  // administrator row (identified by the secret BOOTSTRAP_ADMIN_EMAIL
  // binding, which migrations cannot read) is promoted to the explicit
  // 'bootadmin' role on sign-in. Access control never depends on this
  // write: the effective role is always derived from the configured email.
  if (
    normalizeEmail(user.email) === config.bootstrapAdminEmail &&
    user.role !== "bootadmin"
  ) {
    await env.PG72_ID_DB.prepare(
      "UPDATE user SET role = 'bootadmin', updatedAt = ? WHERE id = ?",
    )
      .bind(new Date().toISOString(), userId)
      .run();
  }
}
