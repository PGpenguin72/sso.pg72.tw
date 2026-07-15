import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

const BASE_URL = "http://localhost:5173";

async function signInSocial(provider: string): Promise<Response> {
  return exports.default.fetch(
    new Request(`${BASE_URL}/sign-in/social`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: BASE_URL },
      body: JSON.stringify({ provider, callbackURL: `${BASE_URL}/` }),
    }),
  );
}

describe("optional social providers", () => {
  it("keeps Google available", async () => {
    const response = await signInSocial("google");
    expect(response.status).toBe(200);
    const body = (await response.json()) as { url?: string; redirect?: boolean };
    expect(body.url).toContain("accounts.google.com");
  });

  it("does not enable providers whose secrets are unset", async () => {
    // Discord/GitHub/Facebook/Apple have no configured client id/secret in the
    // test environment, so Better Auth must not treat them as valid providers.
    for (const provider of ["discord", "github", "facebook", "apple"]) {
      const response = await signInSocial(provider);
      expect(response.status).not.toBe(200);
    }
  });
});
