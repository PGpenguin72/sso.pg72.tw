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

export async function createAuthenticatedUser(
  email: string,
  role: "admin" | "user" = "user",
  options: { googleAccount?: boolean } = {},
) {
  const userId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const token = crypto.randomUUID();
  // Real users sign up through Google, so a linked google account row exists
  // by default; pass { googleAccount: false } to model passkey-only accounts.
  const googleAccountId = options.googleAccount === false ? null : crypto.randomUUID();
  const now = new Date();

  const statements = [
    env.PG72_ID_DB.prepare(
      `INSERT INTO user
        (id, name, email, emailVerified, createdAt, updatedAt, role, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      userId,
      "Test User",
      email,
      1,
      now.toISOString(),
      now.toISOString(),
      role,
      "active",
    ),
    env.PG72_ID_DB.prepare(
      `INSERT INTO session
        (id, expiresAt, token, createdAt, updatedAt, userId)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(
      sessionId,
      new Date(now.getTime() + 60 * 60 * 1000).toISOString(),
      token,
      now.toISOString(),
      now.toISOString(),
      userId,
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

  const signedToken = `${token}.${await makeSignature(token, env.BETTER_AUTH_SECRET)}`;
  const headers = new Headers({
    "Content-Type": "application/json",
    Origin: "http://localhost:5173",
    Cookie: [
      `pg72_id.session_token=${signedToken}`,
      `__Secure-pg72_id.session_token=${signedToken}`,
    ].join("; "),
  });
  return { googleAccountId, headers, sessionId, token, userId };
}
