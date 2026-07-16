import { env } from "cloudflare:workers";
import { makeSignature } from "better-auth/crypto";

export async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export type TestPlatformRole = "admin" | "bootadmin" | "developer" | "user";
export type TestAccountAccessLevel = "restricted" | "standard";

export async function grantPasskeyStepUpForTest(
  userId: string,
  sessionId: string,
  verifiedAt = new Date(),
): Promise<void> {
  const now = new Date().toISOString();
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `INSERT INTO passkey
        (id, name, publicKey, userId, credentialID, counter, deviceType,
         backedUp, transports, createdAt, aaguid)
       SELECT ?, ?, ?, ?, ?, 0, 'singleDevice', 0, '', ?, NULL
        WHERE NOT EXISTS (SELECT 1 FROM passkey WHERE userId = ?)`,
    ).bind(
      crypto.randomUUID(),
      "Test-only step-up credential",
      btoa("test-only-placeholder-public-key"),
      userId,
      crypto.randomUUID(),
      now,
      userId,
    ),
    env.PG72_ID_DB.prepare(
      `UPDATE session SET passkeyStepUpAt = ? WHERE id = ? AND userId = ?`,
    ).bind(verifiedAt.toISOString(), sessionId, userId),
  ]);
}

export async function createSessionFor(userId: string) {
  const sessionId = crypto.randomUUID();
  const token = crypto.randomUUID();
  const now = new Date();

  await env.PG72_ID_DB.prepare(
    `INSERT INTO session
      (id, expiresAt, token, createdAt, updatedAt, userId)
     VALUES (?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      sessionId,
      new Date(now.getTime() + 60 * 60 * 1000).toISOString(),
      token,
      now.toISOString(),
      now.toISOString(),
      userId,
    )
    .run();

  const signedToken = `${token}.${await makeSignature(token, env.BETTER_AUTH_SECRET)}`;
  const headers = new Headers({
    "Content-Type": "application/json",
    Origin: "http://localhost:5173",
    Cookie: [
      `pg72_id.session_token=${signedToken}`,
      `__Secure-pg72_id.session_token=${signedToken}`,
    ].join("; "),
  });
  return { headers, sessionId, token, userId };
}

export async function createAuthenticatedUser(
  email: string,
  role: TestPlatformRole = "user",
  options: {
    accessLevel?: TestAccountAccessLevel;
    googleAccount?: boolean;
    passkeyStepUp?: boolean;
  } = {},
) {
  const userId = crypto.randomUUID();
  // Real users sign up through Google, so a linked google account row exists
  // by default; pass { googleAccount: false } to model passkey-only accounts.
  const googleAccountId =
    options.googleAccount === false ? null : crypto.randomUUID();
  const now = new Date();
  const accessLevel = options.accessLevel ?? "standard";
  const publicAcceptance =
    accessLevel === "restricted" ? "2026-07-17.test" : null;

  const statements = [
    env.PG72_ID_DB.prepare(
      `INSERT INTO user
        (id, name, email, emailVerified, createdAt, updatedAt, role, status,
         accessLevel, termsAcceptedVersion, privacyAcceptedVersion,
         legalAcceptedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      userId,
      "Test User",
      email,
      1,
      now.toISOString(),
      now.toISOString(),
      role,
      "active",
      accessLevel,
      publicAcceptance,
      publicAcceptance,
      accessLevel === "restricted" ? now.toISOString() : null,
    ),
  ];
  if (googleAccountId) {
    statements.push(
      env.PG72_ID_DB.prepare(
        `INSERT INTO account
          (id, accountId, providerId, userId, createdAt, updatedAt)
         VALUES (?, ?, 'google', ?, ?, ?)`,
      ).bind(
        googleAccountId,
        crypto.randomUUID(),
        userId,
        now.toISOString(),
        now.toISOString(),
      ),
    );
  }
  await env.PG72_ID_DB.batch(statements);

  const session = await createSessionFor(userId);
  if (options.passkeyStepUp) {
    await grantPasskeyStepUpForTest(userId, session.sessionId);
  }
  return { ...session, accessLevel, googleAccountId };
}

/**
 * Returns a session for the bootstrap administrator (BOOTSTRAP_ADMIN_EMAIL).
 * The row is created on first use with the pre-migration legacy stored role
 * 'user', so every test exercising bootadmin powers also proves that the
 * effective role is derived from the configured email rather than from the
 * stored role. Storage persists within a test file, so the row is reused.
 */
export async function createBootstrapAdmin() {
  const email = env.BOOTSTRAP_ADMIN_EMAIL.trim().toLowerCase();
  const existing = await env.PG72_ID_DB.prepare(
    "SELECT id FROM user WHERE email = ? LIMIT 1",
  )
    .bind(email)
    .first<{ id: string }>();
  if (existing) {
    return createSessionFor(existing.id);
  }
  return createAuthenticatedUser(email, "user");
}
