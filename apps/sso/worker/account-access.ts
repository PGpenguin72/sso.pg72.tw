import { recordAudit, type WaitUntilContext } from "./audit";

export const ACCOUNT_ACCESS_LEVELS = ["standard", "restricted"] as const;
export type AccountAccessLevel = (typeof ACCOUNT_ACCESS_LEVELS)[number];

export interface AccountAccessState {
  accessLevel: AccountAccessLevel;
  status: string;
}

interface ProviderInsertState extends AccountAccessState {
  legalAcceptedAt: string | null;
  loginMethodCount: number;
}

export function accountAccessLevel(value: unknown): AccountAccessLevel {
  return value === "standard" ? "standard" : "restricted";
}

export async function readAccountAccessState(
  env: Env,
  userId: string,
): Promise<AccountAccessState | null> {
  const row = await env.PG72_ID_DB.prepare(
    "SELECT accessLevel, status FROM user WHERE id = ? LIMIT 1",
  )
    .bind(userId)
    .first<{ accessLevel: unknown; status: string }>();
  return row
    ? { accessLevel: accountAccessLevel(row.accessLevel), status: row.status }
    : null;
}

/**
 * Mirrors migration 0017's provider-link trigger. The only restricted-account
 * exception is the first Google account created in the same public-signup
 * flow as a versioned legal acceptance. The trigger remains the race winner.
 */
export async function providerAccountInsertAllowed(
  env: Env,
  userId: string,
  providerId: string,
): Promise<boolean> {
  const row = await env.PG72_ID_DB.prepare(
    `SELECT u.accessLevel, u.status, u.legalAcceptedAt,
            ((SELECT COUNT(*) FROM account a WHERE a.userId = u.id) +
             (SELECT COUNT(*) FROM passkey p WHERE p.userId = u.id))
              AS loginMethodCount
       FROM user u
      WHERE u.id = ?
      LIMIT 1`,
  )
    .bind(userId)
    .first<{
      accessLevel: unknown;
      legalAcceptedAt: string | null;
      loginMethodCount: number;
      status: string;
    }>();
  if (!row || row.status !== "active") return false;
  const state: ProviderInsertState = {
    accessLevel: accountAccessLevel(row.accessLevel),
    legalAcceptedAt: row.legalAcceptedAt,
    loginMethodCount: row.loginMethodCount,
    status: row.status,
  };
  if (state.accessLevel === "standard") return true;
  return (
    providerId === "google" &&
    state.legalAcceptedAt !== null &&
    state.loginMethodCount === 0
  );
}

export async function recordRestrictedActionDenied(
  env: Env,
  userId: string,
  surface: string,
  executionCtx?: WaitUntilContext,
): Promise<void> {
  await recordAudit(
    env,
    {
      eventType: "account.restricted_action_denied",
      outcome: "denied",
      subjectId: userId,
      metadata: { surface },
    },
    executionCtx,
  );
}
