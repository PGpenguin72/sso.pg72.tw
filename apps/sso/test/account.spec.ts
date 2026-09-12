import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import { linkableProviders, normalizeDisplayName } from "../worker/account";
import { sha256Base64Url } from "../worker/recovery-codes";
import { createAuthenticatedUser } from "./helpers";

const BASE_URL = "http://localhost:5173";

async function createPasskey(userId: string, name: string): Promise<string> {
  const id = crypto.randomUUID();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO passkey
      (id, name, publicKey, userId, credentialID, counter, deviceType,
       backedUp, transports, createdAt, aaguid)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id,
      name,
      "test-public-key",
      userId,
      crypto.randomUUID(),
      0,
      "singleDevice",
      0,
      "internal",
      new Date().toISOString(),
      "00000000-0000-0000-0000-000000000000",
    )
    .run();
  return id;
}

async function createUnusedRecoveryCode(userId: string): Promise<void> {
  const setId = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `INSERT INTO recovery_code_set
        (id, user_id, generation, format_version, created_at, expires_at)
       VALUES (?, ?, 1, 1, ?, NULL)`,
    ).bind(setId, userId, now),
    env.PG72_ID_DB.prepare(
      `INSERT INTO recovery_code
        (id, set_id, ordinal, code_hash, consumed_at)
       VALUES (?, ?, 1, ?, NULL)`,
    ).bind(
      crypto.randomUUID(),
      setId,
      await sha256Base64Url(`account-test-${crypto.randomUUID()}`),
    ),
  ]);
}

async function latestAuditEvent(
  subjectId: string,
): Promise<{ event_type: string; outcome: string } | null> {
  return env.PG72_ID_DB.prepare(
    `SELECT event_type, outcome
       FROM audit_event
      WHERE subject_id = ?
      ORDER BY occurred_at DESC, id DESC
      LIMIT 1`,
  )
    .bind(subjectId)
    .first<{ event_type: string; outcome: string }>();
}

describe("display name validation", () => {
  it("strips control and format characters and trims whitespace", () => {
    expect(
      normalizeDisplayName("  Ada\0\u202e Lovelace\u200b  "),
    ).toBe("Ada Lovelace");
  });

  it("rejects names that are empty after normalization", () => {
    expect(normalizeDisplayName("")).toBeNull();
    expect(normalizeDisplayName("   ")).toBeNull();
    expect(normalizeDisplayName("\0\u200b\u202e")).toBeNull();
  });

  it("enforces the length boundary after normalization", () => {
    expect(normalizeDisplayName("a".repeat(64))).toBe("a".repeat(64));
    expect(normalizeDisplayName(`  ${"a".repeat(64)}  `)).toBe("a".repeat(64));
    expect(normalizeDisplayName("a".repeat(65))).toBeNull();
    expect(normalizeDisplayName("a".repeat(5000))).toBeNull();
  });

  it("rejects non-string input", () => {
    expect(normalizeDisplayName(42)).toBeNull();
    expect(normalizeDisplayName(null)).toBeNull();
    expect(normalizeDisplayName(["x"])).toBeNull();
  });
});

describe("profile updates", () => {
  it("updates the display name and records an audit event", async () => {
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/profile`, {
        method: "POST",
        headers,
        body: JSON.stringify({ name: "  Ada\0 Lovelace\u200b  " }),
      }),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ name: "Ada Lovelace" });
    const user = await env.PG72_ID_DB.prepare(
      "SELECT name FROM user WHERE id = ?",
    )
      .bind(userId)
      .first<{ name: string }>();
    expect(user?.name).toBe("Ada Lovelace");
    expect(await latestAuditEvent(userId)).toEqual({
      event_type: "user.profile_updated",
      outcome: "success",
    });
  });

  it("rejects names that exceed the limit or normalize to empty", async () => {
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    for (const name of ["", "   ", "\0\u200b", "a".repeat(65)]) {
      const response = await exports.default.fetch(
        new Request(`${BASE_URL}/api/account/profile`, {
          method: "POST",
          headers,
          body: JSON.stringify({ name }),
        }),
      );
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "invalid_name" });
    }
    const user = await env.PG72_ID_DB.prepare(
      "SELECT name FROM user WHERE id = ?",
    )
      .bind(userId)
      .first<{ name: string }>();
    expect(user?.name).toBe("Test User");
  });

  it("rejects unauthenticated and cross-origin profile updates", async () => {
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    const unauthenticated = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/profile`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: BASE_URL,
        },
        body: JSON.stringify({ name: "Attacker" }),
      }),
    );
    expect(unauthenticated.status).toBe(401);

    const crossOriginHeaders = new Headers(headers);
    crossOriginHeaders.set("Origin", "https://attacker.example");
    const crossOrigin = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/profile`, {
        method: "POST",
        headers: crossOriginHeaders,
        body: JSON.stringify({ name: "Attacker" }),
      }),
    );
    expect(crossOrigin.status).toBe(403);
    expect(await crossOrigin.json()).toEqual({ error: "invalid_origin" });

    const user = await env.PG72_ID_DB.prepare(
      "SELECT name FROM user WHERE id = ?",
    )
      .bind(userId)
      .first<{ name: string }>();
    expect(user?.name).toBe("Test User");
  });

  it("rejects requests without a recognized field", async () => {
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/profile`, {
        method: "POST",
        headers,
        body: JSON.stringify({}),
      }),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  it("blocks the disabled Better Auth update-user path", async () => {
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/update-user`, {
        method: "POST",
        headers,
        body: JSON.stringify({ name: "\0bypassed" }),
      }),
    );
    expect(response.status).toBe(404);
    const user = await env.PG72_ID_DB.prepare(
      "SELECT name FROM user WHERE id = ?",
    )
      .bind(userId)
      .first<{ name: string }>();
    expect(user?.name).toBe("Test User");
  });
});

describe("avatar selection", () => {
  it("switches to the generated avatar and back without losing the Google image", async () => {
    const googleImage = "https://lh3.googleusercontent.com/a/test-photo";
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await env.PG72_ID_DB.prepare("UPDATE user SET image = ? WHERE id = ?")
      .bind(googleImage, userId)
      .run();

    const generated = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/profile`, {
        method: "POST",
        headers,
        body: JSON.stringify({ avatar: "generated" }),
      }),
    );
    expect(generated.status).toBe(200);
    expect(await generated.json()).toMatchObject({
      avatarSource: "generated",
      image: `${BASE_URL}/api/avatar/v1/${userId}.svg`,
    });
    let user = await env.PG72_ID_DB.prepare(
      "SELECT image, googleImage FROM user WHERE id = ?",
    )
      .bind(userId)
      .first<{ image: string | null; googleImage: string | null }>();
    expect(user).toEqual({
      image: `${BASE_URL}/api/avatar/v1/${userId}.svg`,
      googleImage,
    });

    const restored = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/profile`, {
        method: "POST",
        headers,
        body: JSON.stringify({ avatar: "google" }),
      }),
    );
    expect(restored.status).toBe(200);
    expect(await restored.json()).toMatchObject({
      avatarSource: "google",
      image: googleImage,
    });
    const restoredUser = await env.PG72_ID_DB.prepare(
      "SELECT image FROM user WHERE id = ?",
    )
      .bind(userId)
      .first<{ image: string | null }>();
    expect(restoredUser?.image).toBe(googleImage);
  });

  it("rejects avatar values outside the allow-list", async () => {
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    for (const avatar of ["https://attacker.example/x.png", "", 42, {}]) {
      const response = await exports.default.fetch(
        new Request(`${BASE_URL}/api/account/profile`, {
          method: "POST",
          headers,
          body: JSON.stringify({ avatar }),
        }),
      );
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "invalid_avatar" });
    }
  });

  it("reports the avatar state through the profile endpoint", async () => {
    const googleImage = "https://lh3.googleusercontent.com/a/profile-photo";
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await env.PG72_ID_DB.prepare("UPDATE user SET image = ? WHERE id = ?")
      .bind(googleImage, userId)
      .run();

    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/profile`, { headers }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      name: "Test User",
      image: googleImage,
      avatarSource: "google",
      generatedAvatarUrl: `${BASE_URL}/api/avatar/v1/${userId}.svg`,
      googleAvatarUrl: googleImage,
    });
  });

  it("serves deterministic cacheable identicons without authentication", async () => {
    const userId = crypto.randomUUID();
    const first = await exports.default.fetch(
      `${BASE_URL}/api/avatar/v1/${userId}.svg`,
    );
    expect(first.status).toBe(200);
    expect(first.headers.get("content-type")).toContain("image/svg+xml");
    expect(first.headers.get("cache-control")).toContain("public");
    expect(first.headers.get("content-security-policy")).toContain(
      "default-src 'self'",
    );
    const firstBody = await first.text();
    expect(firstBody).toContain("<svg");
    expect(firstBody).not.toContain("<script");

    const second = await exports.default.fetch(
      `${BASE_URL}/api/avatar/v1/${userId}.svg`,
    );
    expect(await second.text()).toBe(firstBody);

    const other = await exports.default.fetch(
      `${BASE_URL}/api/avatar/v1/${crypto.randomUUID()}.svg`,
    );
    expect(await other.text()).not.toBe(firstBody);
  });

  it("rejects malformed avatar identifiers", async () => {
    for (const file of ["not-a-uuid.svg", "..%2Fsecret", "0".repeat(200)]) {
      const response = await exports.default.fetch(
        `${BASE_URL}/api/avatar/v1/${file}`,
      );
      expect(response.status).toBe(404);
    }
  });
});

describe("login methods", () => {
  it("offers Telegram linking only when the complete widget config exists", () => {
    expect(linkableProviders({})).toEqual(["google"]);
    expect(
      linkableProviders({
        telegramBotToken: "test-token",
        telegramBotUsername: "pgid_test_bot",
      }),
    ).toEqual(["google", "telegram"]);
    expect(
      linkableProviders({
        telegramBotToken: "test-token",
        telegramBotUsername: "   ",
      }),
    ).toEqual(["google"]);
  });

  it("lists linked providers and passkeys for the signed-in user", async () => {
    const { googleAccountId, headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await createPasskey(userId, "Key A");
    await createPasskey(userId, "Key B");

    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/login-methods`, { headers }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      accessLevel: "standard",
      providers: [
        expect.objectContaining({
          id: googleAccountId,
          provider: "google",
          canUnlink: false,
          recoveryCodeRequired: true,
        }),
      ],
      passkeyCount: 2,
      linkable: [],
    });
  });

  it("requires a session to list login methods", async () => {
    const response = await exports.default.fetch(
      `${BASE_URL}/api/account/login-methods`,
    );
    expect(response.status).toBe(401);
  });

  it("unlinks Google while a passkey remains and records an audit event", async () => {
    const { googleAccountId, headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await createPasskey(userId, "Remaining key");
    await createUnusedRecoveryCode(userId);

    const response = await exports.default.fetch(
      new Request(
        `${BASE_URL}/api/account/login-methods/${googleAccountId}`,
        { method: "DELETE", headers },
      ),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      unlinked: true,
      provider: "google",
    });
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM account WHERE id = ?")
        .bind(googleAccountId)
        .first(),
    ).toBeNull();
    expect(await latestAuditEvent(userId)).toEqual({
      event_type: "account.unlinked",
      outcome: "success",
    });
  });

  it("blocks unlinking the final social provider without an unused recovery code", async () => {
    const { googleAccountId, headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await createPasskey(userId, "Passkey-only transition");

    const response = await exports.default.fetch(
      new Request(
        `${BASE_URL}/api/account/login-methods/${googleAccountId}`,
        { method: "DELETE", headers },
      ),
    );
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "recovery_code_required" });
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM account WHERE id = ?")
        .bind(googleAccountId)
        .first(),
    ).not.toBeNull();
  });

  it("refuses to unlink the last remaining sign-in method", async () => {
    const { googleAccountId, headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    const response = await exports.default.fetch(
      new Request(
        `${BASE_URL}/api/account/login-methods/${googleAccountId}`,
        { method: "DELETE", headers },
      ),
    );
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "last_login_method" });
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM account WHERE id = ?")
        .bind(googleAccountId)
        .first(),
    ).not.toBeNull();
    expect(await latestAuditEvent(userId)).toEqual({
      event_type: "account.unlink_blocked",
      outcome: "denied",
    });
  });

  it("cannot unlink another user's account", async () => {
    const owner = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await createPasskey(owner.userId, "Owner key");
    const attacker = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    const response = await exports.default.fetch(
      new Request(
        `${BASE_URL}/api/account/login-methods/${owner.googleAccountId}`,
        { method: "DELETE", headers: attacker.headers },
      ),
    );
    expect(response.status).toBe(404);
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM account WHERE id = ?")
        .bind(owner.googleAccountId)
        .first(),
    ).not.toBeNull();
  });

  it("rejects unauthenticated and cross-origin unlink requests", async () => {
    const { googleAccountId, headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await createPasskey(userId, "Key");

    const unauthenticated = await exports.default.fetch(
      new Request(
        `${BASE_URL}/api/account/login-methods/${googleAccountId}`,
        {
          method: "DELETE",
          headers: { Origin: BASE_URL },
        },
      ),
    );
    expect(unauthenticated.status).toBe(401);

    const crossOriginHeaders = new Headers(headers);
    crossOriginHeaders.set("Origin", "https://attacker.example");
    const crossOrigin = await exports.default.fetch(
      new Request(
        `${BASE_URL}/api/account/login-methods/${googleAccountId}`,
        { method: "DELETE", headers: crossOriginHeaders },
      ),
    );
    expect(crossOrigin.status).toBe(403);
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM account WHERE id = ?")
        .bind(googleAccountId)
        .first(),
    ).not.toBeNull();
  });

  it("blocks deleting the last passkey when no linked account remains", async () => {
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "user",
      { googleAccount: false },
    );
    const passkeyId = await createPasskey(userId, "Only key");

    // The session is fresh, but freshness cannot override the policy that at
    // least one sign-in method must remain.
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/passkey/delete-passkey`, {
        method: "POST",
        headers,
        body: JSON.stringify({ id: passkeyId }),
      }),
    );
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({
      error: "last_login_method",
    });
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM passkey WHERE id = ?")
        .bind(passkeyId)
        .first(),
    ).not.toBeNull();
  });

  it("requires a session to start linking a provider", async () => {
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/link-social`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: BASE_URL,
        },
        body: JSON.stringify({
          provider: "google",
          callbackURL: `${BASE_URL}/`,
        }),
      }),
    );
    expect(response.status).toBe(401);
  });

  it("rejects cross-origin link initiation", async () => {
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const crossOriginHeaders = new Headers(headers);
    crossOriginHeaders.set("Origin", "https://attacker.example");

    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/link-social`, {
        method: "POST",
        headers: crossOriginHeaders,
        body: JSON.stringify({
          provider: "google",
          callbackURL: `${BASE_URL}/`,
        }),
      }),
    );
    expect(response.status).toBe(403);
  });
});
