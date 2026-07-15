import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import { verifyTelegramAuth } from "../worker/telegram";
import { createAuthenticatedUser } from "./helpers";

const BASE_URL = "http://localhost:5173";
// Must match the TELEGRAM_BOT_TOKEN binding injected by vitest.config.ts.
const BOT_TOKEN = "123456:AAvitest-telegram-bot-token";

function randomTelegramId(): string {
  const buffer = new Uint32Array(2);
  crypto.getRandomValues(buffer);
  return `${buffer[0]}${buffer[1]}`.slice(0, 15);
}

async function signTelegram(
  data: Record<string, string>,
  token: string,
): Promise<string> {
  const dataCheckString = Object.keys(data)
    .filter((key) => key !== "hash")
    .sort()
    .map((key) => `${key}=${data[key]}`)
    .join("\n");
  const secretKey = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token),
  );
  const key = await crypto.subtle.importKey(
    "raw",
    secretKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(dataCheckString),
  );
  return [...new Uint8Array(signature)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function telegramPayload(
  overrides: Partial<Record<string, string>> = {},
): Promise<Record<string, string>> {
  const data: Record<string, string> = {
    id: randomTelegramId(),
    first_name: "Tele",
    username: "tele_user",
    auth_date: String(Math.floor(Date.now() / 1000)),
    ...overrides,
  };
  data.hash = await signTelegram(data, BOT_TOKEN);
  return data;
}

describe("verifyTelegramAuth", () => {
  it("accepts a correctly signed, fresh payload", async () => {
    const data = await telegramPayload({ id: "42" });
    const result = await verifyTelegramAuth(data, BOT_TOKEN, Date.now());
    expect(result).toMatchObject({ ok: true });
    if (result.ok) {
      expect(result.user.id).toBe("42");
      expect(result.user.username).toBe("tele_user");
    }
  });

  it("rejects a tampered hash", async () => {
    const data = await telegramPayload({ id: "43" });
    data.first_name = "Attacker"; // hash no longer matches
    const result = await verifyTelegramAuth(data, BOT_TOKEN, Date.now());
    expect(result).toEqual({ ok: false, error: "invalid_telegram_hash" });
  });

  it("rejects a stale payload (replay window)", async () => {
    const data = await telegramPayload({
      id: "44",
      auth_date: String(Math.floor(Date.now() / 1000) - 10_000),
    });
    const result = await verifyTelegramAuth(data, BOT_TOKEN, Date.now());
    expect(result).toEqual({ ok: false, error: "telegram_auth_expired" });
  });

  it("rejects a payload without a numeric id", async () => {
    const data = await telegramPayload({ id: "not-a-number" });
    const result = await verifyTelegramAuth(data, BOT_TOKEN, Date.now());
    expect(result.ok).toBe(false);
  });
});

/** Seeds a Telegram-linked account directly (used to test sign-in). */
async function seedTelegramAccount(telegramId: string): Promise<string> {
  const userId = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `INSERT INTO user
        (id, name, email, emailVerified, createdAt, updatedAt, role, status)
       VALUES (?, 'Tele', ?, 0, ?, ?, 'user', 'active')`,
    ).bind(userId, `tg_${telegramId}@telegram.invalid`, now, now),
    env.PG72_ID_DB.prepare(
      `INSERT INTO account
        (id, accountId, providerId, userId, createdAt, updatedAt)
       VALUES (?, ?, 'telegram', ?, ?, ?)`,
    ).bind(crypto.randomUUID(), telegramId, userId, now, now),
  ]);
  return userId;
}

describe("telegram config endpoint", () => {
  it("reports enabled with the bot username when configured", async () => {
    // The ambient test env injects a deterministic TELEGRAM_BOT_TOKEN; the
    // username is exposed publicly so the sign-in widget can render.
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/auth/telegram/config`, {
        headers: { accept: "application/json" },
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      enabled: boolean;
      botUsername: string | null;
    };
    // enabled requires BOTH a token and a username; the token is present in the
    // test env. Whether a username is set depends on the test env, so assert the
    // shape and the invariant (enabled implies a non-null username).
    expect(typeof body.enabled).toBe("boolean");
    if (body.enabled) expect(body.botUsername).toBeTruthy();
    else expect(body.botUsername === null || typeof body.botUsername === "string").toBe(true);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});

describe("telegram login endpoint", () => {
  it("signs in an existing Telegram account and records the login", async () => {
    const telegramId = randomTelegramId();
    const userId = await seedTelegramAccount(telegramId);

    const signedIn = await exports.default.fetch(
      new Request(`${BASE_URL}/api/auth/telegram`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: BASE_URL },
        body: JSON.stringify(await telegramPayload({ id: telegramId })),
      }),
    );
    expect(signedIn.status).toBe(200);
    const body = (await signedIn.json()) as { signedIn: boolean; created?: boolean };
    expect(body.signedIn).toBe(true);
    expect(body.created).toBeUndefined();
    expect(signedIn.headers.get("set-cookie")).toContain("session_token=");

    const login = await env.PG72_ID_DB.prepare(
      `SELECT metadata_json FROM audit_event
        WHERE subject_id = ? AND event_type = 'user.login_succeeded'
        ORDER BY occurred_at DESC LIMIT 1`,
    )
      .bind(userId)
      .first<{ metadata_json: string }>();
    expect(login?.metadata_json).toContain('"provider":"telegram"');
  });

  it("refuses a new Telegram sign-up under invite registration mode", async () => {
    // The ambient test env runs REGISTRATION_MODE=invite; Telegram has no email
    // to match an invitation, so a brand-new sign-up is refused.
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/auth/telegram`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: BASE_URL },
        body: JSON.stringify(await telegramPayload({ id: randomTelegramId() })),
      }),
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "registration_closed" });
  });

  it("rejects a bad hash and a cross-origin request", async () => {
    const badHash = await exports.default.fetch(
      new Request(`${BASE_URL}/api/auth/telegram`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: BASE_URL },
        body: JSON.stringify({
          ...(await telegramPayload({ id: randomTelegramId() })),
          hash: "0".repeat(64),
        }),
      }),
    );
    expect(badHash.status).toBe(400);
    expect(await badHash.json()).toEqual({ error: "invalid_telegram_hash" });

    const crossOrigin = await exports.default.fetch(
      new Request(`${BASE_URL}/api/auth/telegram`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: "https://attacker.example",
        },
        body: JSON.stringify(await telegramPayload({ id: randomTelegramId() })),
      }),
    );
    expect(crossOrigin.status).toBe(403);
  });
});

describe("telegram linking", () => {
  it("links Telegram to the signed-in account and blocks a second owner", async () => {
    const telegramId = randomTelegramId();
    const first = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    const linked = await exports.default.fetch(
      new Request(`${BASE_URL}/api/auth/telegram/link`, {
        method: "POST",
        headers: first.headers,
        body: JSON.stringify(await telegramPayload({ id: telegramId })),
      }),
    );
    expect(linked.status).toBe(200);
    expect(await linked.json()).toEqual({ linked: true, provider: "telegram" });

    const row = await env.PG72_ID_DB.prepare(
      "SELECT userId FROM account WHERE providerId = 'telegram' AND accountId = ?",
    )
      .bind(telegramId)
      .first<{ userId: string }>();
    expect(row?.userId).toBe(first.userId);

    // A different user cannot claim the same immutable Telegram identity.
    const second = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const conflict = await exports.default.fetch(
      new Request(`${BASE_URL}/api/auth/telegram/link`, {
        method: "POST",
        headers: second.headers,
        body: JSON.stringify(await telegramPayload({ id: telegramId })),
      }),
    );
    expect(conflict.status).toBe(409);
    expect(await conflict.json()).toEqual({ error: "telegram_already_linked" });
  });

  it("requires an authenticated session to link", async () => {
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/auth/telegram/link`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: BASE_URL },
        body: JSON.stringify(await telegramPayload({ id: randomTelegramId() })),
      }),
    );
    expect(response.status).toBe(401);
  });
});
