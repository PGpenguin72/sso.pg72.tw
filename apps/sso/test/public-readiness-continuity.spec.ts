import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import { createAuth } from "../worker/auth";

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(
    normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "="),
  );
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function signatureValid(
  token: string,
  keys: Array<JsonWebKey & { kid: string }>,
): Promise<boolean> {
  const segments = token.split(".");
  if (segments.length !== 3) return false;
  const [header, payload, signature] = segments;
  const parsed = JSON.parse(
    new TextDecoder().decode(decodeBase64Url(header)),
  ) as { alg?: string; kid?: string };
  const key = keys.find(({ kid }) => kid === parsed.kid);
  if (!key || parsed.alg !== "EdDSA") return false;
  const imported = await crypto.subtle.importKey(
    "jwk",
    key,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "Ed25519" },
    imported,
    decodeBase64Url(signature),
    new TextEncoder().encode(`${header}.${payload}`),
  );
}

async function publicKeys(): Promise<Array<JsonWebKey & { kid: string }>> {
  const response = await exports.default.fetch(
    new Request("http://localhost:5173/.well-known/jwks.json"),
  );
  expect(response.status).toBe(200);
  const payload = (await response.json()) as {
    keys: Array<JsonWebKey & { kid: string }>;
  };
  return payload.keys;
}

describe("public-readiness signing-key continuity", () => {
  it("signs with restored keys across overlap and rejects a retired kid", async () => {
    const auth = createAuth(env);
    const first = await auth.api.signJWT({
      body: { payload: { marker: "continuity-a", sub: crypto.randomUUID() } },
    });
    const firstHeader = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(first.token.split(".")[0] ?? "")),
    ) as { kid: string };
    await env.PG72_ID_DB.prepare(
      "UPDATE jwks SET expiresAt = ? WHERE id = ?",
    )
      .bind(new Date(Date.now() - 86_400_000).toISOString(), firstHeader.kid)
      .run();

    const second = await auth.api.signJWT({
      body: { payload: { marker: "continuity-b", sub: crypto.randomUUID() } },
    });
    const secondHeader = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(second.token.split(".")[0] ?? "")),
    ) as { kid: string };
    expect(secondHeader.kid).not.toBe(firstHeader.kid);

    const overlap = await publicKeys();
    expect(overlap.map(({ kid }) => kid)).toEqual(
      expect.arrayContaining([firstHeader.kid, secondHeader.kid]),
    );
    expect(await signatureValid(first.token, overlap)).toBe(true);
    expect(await signatureValid(second.token, overlap)).toBe(true);

    await env.PG72_ID_DB.prepare(
      "UPDATE jwks SET expiresAt = ? WHERE id = ?",
    )
      .bind(new Date(Date.now() - 61 * 86_400_000).toISOString(), firstHeader.kid)
      .run();
    const retired = await publicKeys();
    expect(retired.some(({ kid }) => kid === firstHeader.kid)).toBe(false);
    expect(retired.some(({ kid }) => kid === secondHeader.kid)).toBe(true);
    expect(await signatureValid(first.token, retired)).toBe(false);
    expect(await signatureValid(second.token, retired)).toBe(true);
  });
});
