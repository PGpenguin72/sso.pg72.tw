import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import { readRuntimeConfig } from "../worker/config";
import {
  assertSessionUserActive,
  authorizeRegistration,
} from "../worker/registration";
import { createAuthenticatedUser } from "./helpers";

const publicEnv = { ...env, REGISTRATION_MODE: "public" } as Env;
const inviteEnv = { ...env, REGISTRATION_MODE: "invite" } as Env;
const publicConfig = readRuntimeConfig(publicEnv);
const inviteConfig = readRuntimeConfig(inviteEnv);

let ipCounter = 0;
function uniqueIp(): string {
  ipCounter += 1;
  return `198.51.100.${ipCounter}`;
}

function randomEmail(): string {
  return `${crypto.randomUUID()}@example.com`;
}

async function createInvitation(
  email: string,
  role: "admin" | "user",
): Promise<void> {
  await env.PG72_ID_DB.prepare(
    `INSERT INTO invitation
      (id, email_normalized, role, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?)`,
  )
    .bind(
      crypto.randomUUID(),
      email,
      role,
      new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      new Date().toISOString(),
    )
    .run();
}

describe("registration policy", () => {
  it("public mode registers a new verified email without an invitation", async () => {
    const grant = await authorizeRegistration(publicEnv, publicConfig, {
      email: randomEmail(),
      emailVerified: true,
      clientIp: uniqueIp(),
    });

    expect(grant).toEqual({ role: "user", status: "active" });
  });

  it("public mode rejects unverified emails", async () => {
    await expect(
      authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: false,
        clientIp: uniqueIp(),
      }),
    ).rejects.toMatchObject({
      body: { code: "EMAIL_NOT_VERIFIED" },
      statusCode: 403,
    });
  });

  it("public mode still honors a pending invitation's role", async () => {
    const email = randomEmail();
    await createInvitation(email, "admin");

    const grant = await authorizeRegistration(publicEnv, publicConfig, {
      email,
      emailVerified: true,
      clientIp: uniqueIp(),
    });

    expect(grant).toEqual({ role: "admin", status: "active" });
  });

  it("public mode grants the bootstrap administrator the bootadmin role", async () => {
    const grant = await authorizeRegistration(publicEnv, publicConfig, {
      email: env.BOOTSTRAP_ADMIN_EMAIL,
      emailVerified: true,
      clientIp: uniqueIp(),
    });

    expect(grant).toEqual({ role: "bootadmin", status: "active" });
  });

  it("invite mode still denies uninvited emails", async () => {
    await expect(
      authorizeRegistration(inviteEnv, inviteConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp: uniqueIp(),
      }),
    ).rejects.toMatchObject({
      body: { code: "INVITATION_REQUIRED" },
      statusCode: 403,
    });
  });

  it("invite mode still registers invited emails with the invited role", async () => {
    const email = randomEmail();
    await createInvitation(email, "user");

    const grant = await authorizeRegistration(inviteEnv, inviteConfig, {
      email,
      emailVerified: true,
      clientIp: uniqueIp(),
    });

    expect(grant).toEqual({ role: "user", status: "active" });
  });

  it("invite mode also rejects unverified emails", async () => {
    const email = randomEmail();
    await createInvitation(email, "user");

    await expect(
      authorizeRegistration(inviteEnv, inviteConfig, {
        email,
        emailVerified: false,
        clientIp: uniqueIp(),
      }),
    ).rejects.toMatchObject({ body: { code: "EMAIL_NOT_VERIFIED" } });
  });

  it("rate limits repeated registrations from a single IP", async () => {
    const clientIp = `203.0.113.${(ipCounter += 1)}`;

    for (let attempt = 0; attempt < 5; attempt += 1) {
      await authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp,
      });
    }

    await expect(
      authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp,
      }),
    ).rejects.toMatchObject({
      body: { code: "REGISTRATION_RATE_LIMITED" },
      statusCode: 429,
    });

    const audit = await env.PG72_ID_DB.prepare(
      `SELECT COUNT(*) AS count FROM audit_event
        WHERE event_type = 'registration.rate_limited'`,
    ).first<{ count: number }>();
    expect(audit?.count ?? 0).toBeGreaterThanOrEqual(1);
  });

  it("does not let a rate-limited IP spam invitation lookups or audit denials", async () => {
    const clientIp = `203.0.113.${(ipCounter += 1)}`;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp,
      });
    }

    const before = await env.PG72_ID_DB.prepare(
      `SELECT COUNT(*) AS count FROM audit_event
        WHERE event_type = 'registration.denied'`,
    ).first<{ count: number }>();

    // Unverified email past the budget: the limiter must win, so the
    // request never reaches the denial audit or the invitation query.
    await expect(
      authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: false,
        clientIp,
      }),
    ).rejects.toMatchObject({ body: { code: "REGISTRATION_RATE_LIMITED" } });

    const after = await env.PG72_ID_DB.prepare(
      `SELECT COUNT(*) AS count FROM audit_event
        WHERE event_type = 'registration.denied'`,
    ).first<{ count: number }>();
    expect(after?.count).toBe(before?.count);
  });

  it("blocks suspended users from creating a session", async () => {
    const { userId } = await createAuthenticatedUser(randomEmail());
    await env.PG72_ID_DB.prepare(
      "UPDATE user SET status = 'suspended' WHERE id = ?",
    )
      .bind(userId)
      .run();

    await expect(
      assertSessionUserActive(env, publicConfig, userId),
    ).rejects.toMatchObject({
      body: { code: "ACCOUNT_SUSPENDED" },
      statusCode: 403,
    });
  });

  it("blocks deleted (missing) users from creating a session", async () => {
    await expect(
      assertSessionUserActive(env, publicConfig, crypto.randomUUID()),
    ).rejects.toMatchObject({ body: { code: "ACCOUNT_SUSPENDED" } });
  });

  it("allows active users to create a session", async () => {
    const { userId } = await createAuthenticatedUser(randomEmail());
    await expect(
      assertSessionUserActive(env, publicConfig, userId),
    ).resolves.toBeUndefined();
  });

  it("keeps passkey registration behind an authenticated session", async () => {
    const response = await exports.default.fetch(
      new Request(
        "http://localhost:5173/passkey/generate-register-options",
        { headers: { "cf-connecting-ip": uniqueIp() } },
      ),
    );

    expect(response.status).toBe(401);
  });
});
