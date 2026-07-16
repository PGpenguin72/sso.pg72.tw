import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import {
  decodeDataUrl,
  detectImageType,
  validateAvatarBytes,
} from "../worker/avatar";
import { createAuthenticatedUser } from "./helpers";

const BASE_URL = "http://localhost:5173";

// 1x1 transparent PNG.
const PNG_1X1_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
const PNG_1X1_DATA_URL = `data:image/png;base64,${PNG_1X1_BASE64}`;

function pngBytes(): Uint8Array<ArrayBuffer> {
  const binary = atob(PNG_1X1_BASE64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function latestAuditEvent(
  subjectId: string,
): Promise<{ event_type: string; outcome: string } | null> {
  return env.PG72_ID_DB.prepare(
    `SELECT event_type, outcome FROM audit_event
      WHERE subject_id = ? ORDER BY occurred_at DESC, id DESC LIMIT 1`,
  )
    .bind(subjectId)
    .first<{ event_type: string; outcome: string }>();
}

describe("avatar byte validation", () => {
  it("detects supported image signatures", () => {
    expect(detectImageType(pngBytes())).toBe("image/png");
    expect(
      detectImageType(new Uint8Array([0xff, 0xd8, 0xff, 0x00])),
    ).toBe("image/jpeg");
    const webp = new Uint8Array(16);
    webp.set([0x52, 0x49, 0x46, 0x46], 0); // RIFF
    webp.set([0x57, 0x45, 0x42, 0x50], 8); // WEBP
    expect(detectImageType(webp)).toBe("image/webp");
    expect(detectImageType(new TextEncoder().encode("hello world!!"))).toBeNull();
  });

  it("rejects empty, oversized, and non-image payloads", () => {
    expect(validateAvatarBytes(new Uint8Array(0))).toEqual({
      ok: false,
      error: "empty_avatar",
    });
    expect(validateAvatarBytes(new Uint8Array(256 * 1024 + 1))).toEqual({
      ok: false,
      error: "avatar_too_large",
    });
    expect(
      validateAvatarBytes(new TextEncoder().encode("not an image at all")),
    ).toEqual({ ok: false, error: "unsupported_avatar_type" });
  });

  it("accepts a valid PNG and reads its dimensions", () => {
    expect(validateAvatarBytes(pngBytes())).toEqual({
      ok: true,
      contentType: "image/png",
      width: 1,
      height: 1,
    });
  });

  it("decodes only well-formed base64 data URLs", () => {
    expect(decodeDataUrl(PNG_1X1_DATA_URL)?.mime).toBe("image/png");
    expect(decodeDataUrl("not-a-data-url")).toBeNull();
    expect(decodeDataUrl("data:image/png;base64,%%%")).toBeNull();
    expect(decodeDataUrl(42)).toBeNull();
  });
});

describe("avatar upload endpoint", () => {
  it("stores a JSON data-URL upload and points the profile at it", async () => {
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar`, {
        method: "POST",
        headers,
        body: JSON.stringify({ dataUrl: PNG_1X1_DATA_URL }),
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      imageUrl: string;
      avatarSource: string;
    };
    expect(body.avatarSource).toBe("upload");
    expect(body.imageUrl.startsWith(`${BASE_URL}/api/account/avatar/`)).toBe(true);

    const user = await env.PG72_ID_DB.prepare(
      "SELECT image FROM user WHERE id = ?",
    )
      .bind(userId)
      .first<{ image: string }>();
    expect(user?.image).toBe(body.imageUrl);
    const stored = await env.PG72_ID_DB.prepare(
      "SELECT content_type, byte_size FROM user_avatar WHERE user_id = ?",
    )
      .bind(userId)
      .first<{ content_type: string; byte_size: number }>();
    expect(stored?.content_type).toBe("image/png");
    expect(stored?.byte_size).toBeGreaterThan(0);
    expect(await latestAuditEvent(userId)).toEqual({
      event_type: "user.avatar_updated",
      outcome: "success",
    });
  });

  it("accepts a multipart upload and replaces the previous avatar", async () => {
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar`, {
        method: "POST",
        headers,
        body: JSON.stringify({ dataUrl: PNG_1X1_DATA_URL }),
      }),
    );

    const form = new FormData();
    form.append("file", new Blob([pngBytes()], { type: "image/png" }), "a.png");
    const multipartHeaders = new Headers(headers);
    multipartHeaders.delete("Content-Type");
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar`, {
        method: "POST",
        headers: multipartHeaders,
        body: form,
      }),
    );
    expect(response.status).toBe(200);

    // Only the latest avatar is retained.
    const count = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM user_avatar WHERE user_id = ?",
    )
      .bind(userId)
      .first<{ count: number }>();
    expect(count?.count).toBe(1);
  });

  it("rejects non-image and oversized uploads", async () => {
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const notImage = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          dataUrl: `data:image/png;base64,${btoa("this is definitely not an image")}`,
        }),
      }),
    );
    expect(notImage.status).toBe(400);
    expect(await notImage.json()).toEqual({ error: "unsupported_avatar_type" });

    const bigBytes = new Uint8Array(256 * 1024 + 10);
    let binary = "";
    for (const byte of bigBytes) binary += String.fromCharCode(byte);
    const oversized = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar`, {
        method: "POST",
        headers,
        body: JSON.stringify({ dataUrl: `data:image/png;base64,${btoa(binary)}` }),
      }),
    );
    expect(oversized.status).toBe(400);
    expect(await oversized.json()).toEqual({ error: "avatar_too_large" });
  });

  it("rejects unauthenticated and cross-origin uploads", async () => {
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );

    const unauthenticated = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: BASE_URL },
        body: JSON.stringify({ dataUrl: PNG_1X1_DATA_URL }),
      }),
    );
    expect(unauthenticated.status).toBe(401);

    const crossOrigin = new Headers(headers);
    crossOrigin.set("Origin", "https://attacker.example");
    const rejected = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar`, {
        method: "POST",
        headers: crossOrigin,
        body: JSON.stringify({ dataUrl: PNG_1X1_DATA_URL }),
      }),
    );
    expect(rejected.status).toBe(403);
    expect(await rejected.json()).toEqual({ error: "invalid_origin" });
  });
});

describe("avatar serving and mode switching", () => {
  it("serves the uploaded bytes publicly with a cacheable content type", async () => {
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const upload = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar`, {
        method: "POST",
        headers,
        body: JSON.stringify({ dataUrl: PNG_1X1_DATA_URL }),
      }),
    );
    const { imageUrl } = (await upload.json()) as { imageUrl: string };

    // No credentials: the picture claim must be fetchable by relying parties.
    const served = await exports.default.fetch(new Request(imageUrl));
    expect(served.status).toBe(200);
    expect(served.headers.get("content-type")).toBe("image/png");
    expect(served.headers.get("cache-control")).toContain("public");
    expect(served.headers.get("cache-control")).not.toContain("no-store");
    expect(new Uint8Array(await served.arrayBuffer())).toEqual(pngBytes());

    const missing = await exports.default.fetch(
      `${BASE_URL}/api/account/avatar/${crypto.randomUUID()}`,
    );
    expect(missing.status).toBe(404);

    void userId;
  });

  it("switches between upload, identicon, and google without losing the Google image", async () => {
    const googleImage = "https://lh3.googleusercontent.com/a/mode-photo";
    const { headers, userId } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    await env.PG72_ID_DB.prepare("UPDATE user SET image = ? WHERE id = ?")
      .bind(googleImage, userId)
      .run();

    // No avatar uploaded yet -> upload mode is unavailable.
    const noAvatar = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar/mode`, {
        method: "POST",
        headers,
        body: JSON.stringify({ mode: "upload" }),
      }),
    );
    expect(noAvatar.status).toBe(409);
    expect(await noAvatar.json()).toEqual({ error: "no_avatar" });

    await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar`, {
        method: "POST",
        headers,
        body: JSON.stringify({ dataUrl: PNG_1X1_DATA_URL }),
      }),
    );

    const toIdenticon = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar/mode`, {
        method: "POST",
        headers,
        body: JSON.stringify({ mode: "identicon" }),
      }),
    );
    expect(toIdenticon.status).toBe(200);
    expect(await toIdenticon.json()).toMatchObject({
      avatarSource: "generated",
      imageUrl: `${BASE_URL}/api/avatar/v1/${userId}.svg`,
    });

    const toGoogle = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar/mode`, {
        method: "POST",
        headers,
        body: JSON.stringify({ mode: "google" }),
      }),
    );
    expect(await toGoogle.json()).toMatchObject({
      avatarSource: "google",
      imageUrl: googleImage,
    });

    const backToUpload = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar/mode`, {
        method: "POST",
        headers,
        body: JSON.stringify({ mode: "upload" }),
      }),
    );
    expect(await backToUpload.json()).toMatchObject({ avatarSource: "upload" });

    const user = await env.PG72_ID_DB.prepare(
      "SELECT googleImage FROM user WHERE id = ?",
    )
      .bind(userId)
      .first<{ googleImage: string }>();
    expect(user?.googleImage).toBe(googleImage);
  });

  it("rejects an invalid mode value", async () => {
    const { headers } = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
    );
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/avatar/mode`, {
        method: "POST",
        headers,
        body: JSON.stringify({ mode: "banana" }),
      }),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_mode" });
  });
});
