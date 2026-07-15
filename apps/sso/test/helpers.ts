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
) {
  const userId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const token = crypto.randomUUID();
  const now = new Date();

  await env.PG72_ID_DB.batch([
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
  ]);

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
