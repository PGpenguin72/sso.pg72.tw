import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";

import { readRuntimeConfig } from "../worker/config";
import worker from "../worker/index";
import {
  assertSessionUserActive,
  authorizeRegistration,
} from "../worker/registration";
import {
  bindPublicRegistrationOAuthState,
  hashPublicRegistrationValue,
  issuePublicRegistrationIntent,
  preparePublicRegistrationOAuthStart,
  PUBLIC_REGISTRATION_STATE_KEY,
  publicRegistrationRoutes,
  registrationBindingFromOAuthState,
  TURNSTILE_REGISTRATION_ACTION,
  verifyTurnstileRegistrationToken,
} from "../worker/public-registration";
import { createAuthenticatedUser } from "./helpers";

const publicEnv = { ...env, REGISTRATION_MODE: "public" } as Env;
const inviteEnv = { ...env, REGISTRATION_MODE: "invite" } as Env;
const githubPublicEnv = {
  ...publicEnv,
  GITHUB_CLIENT_ID: "test-github-client-id",
  GITHUB_CLIENT_SECRET: "test-github-client-secret",
} as Env;
const publicConfig = readRuntimeConfig(publicEnv);
const inviteConfig = readRuntimeConfig(inviteEnv);

function testExecutionContext(): ExecutionContext {
  return {
    waitUntil: () => undefined,
  } as unknown as ExecutionContext;
}

let ipCounter = 0;
function uniqueIp(): string {
  ipCounter += 1;
  return `198.51.100.${ipCounter}`;
}

function randomEmail(): string {
  return `${crypto.randomUUID()}@example.com`;
}

function base64UrlJson(value: unknown): string {
  return btoa(JSON.stringify(value))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function testGoogleIdToken(email: string): string {
  const now = Math.floor(Date.now() / 1000);
  return [
    base64UrlJson({ alg: "none", typ: "JWT" }),
    base64UrlJson({
      aud: publicEnv.GOOGLE_CLIENT_ID,
      email,
      email_verified: true,
      exp: now + 300,
      iat: now,
      iss: "https://accounts.google.com",
      name: "Public registration test",
      sub: crypto.randomUUID(),
    }),
    "test-signature",
  ].join(".");
}

const verifiedTurnstileFetch: typeof fetch = async (_input, init) => {
  const form = init?.body;
  expect(form).toBeInstanceOf(FormData);
  expect((form as FormData).get("secret")).toBe(
    publicConfig.publicRegistration?.turnstileSecretKey,
  );
  return Response.json({
    action: TURNSTILE_REGISTRATION_ACTION,
    hostname: "localhost",
    success: true,
  });
};

async function createPublicRegistrationIntent(clientIp = uniqueIp()) {
  return issuePublicRegistrationIntent(
    publicEnv,
    publicConfig,
    {
      acceptPrivacy: true,
      acceptTerms: true,
      privacyVersion: publicConfig.publicRegistration?.privacyVersion,
      termsVersion: publicConfig.publicRegistration?.termsVersion,
      turnstileToken: `test-turnstile-${crypto.randomUUID()}`,
    },
    clientIp,
    undefined,
    verifiedTurnstileFetch,
  );
}

async function createPublicRegistrationBinding(clientIp = uniqueIp()) {
  const intent = await createPublicRegistrationIntent(clientIp);
  const prepared = await preparePublicRegistrationOAuthStart(
    publicEnv,
    publicConfig,
    intent.intentId,
  );
  const oauthState = crypto.randomUUID();
  await bindPublicRegistrationOAuthState(
    publicEnv,
    publicConfig,
    prepared,
    oauthState,
  );
  return {
    intent,
    prepared,
    registrationBinding: {
      oauthReference: prepared.oauthReference,
      oauthState,
    },
  };
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
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("reads only the secondary reference bound to Better Auth OAuth state", () => {
    const oauthReference = "A".repeat(43);
    const oauthState = "B".repeat(32);
    expect(
      registrationBindingFromOAuthState({
        [PUBLIC_REGISTRATION_STATE_KEY]: oauthReference,
        oauthState,
      }),
    ).toEqual({ oauthReference, oauthState });
    expect(registrationBindingFromOAuthState(null)).toBeUndefined();
    expect(
      registrationBindingFromOAuthState({
        [PUBLIC_REGISTRATION_STATE_KEY]: 42,
        oauthState,
      }),
    ).toBeUndefined();
    expect(
      registrationBindingFromOAuthState({
        [PUBLIC_REGISTRATION_STATE_KEY]: oauthReference,
      }),
    ).toBeUndefined();
  });

  it("requires all public-registration bindings only in public mode", () => {
    expect(
      readRuntimeConfig({
        ...inviteEnv,
        PRIVACY_VERSION: undefined,
        TERMS_VERSION: undefined,
        TURNSTILE_SECRET_KEY: undefined,
        TURNSTILE_SITE_KEY: undefined,
      }).publicRegistration,
    ).toBeNull();
    for (const binding of [
      "PRIVACY_VERSION",
      "TERMS_VERSION",
      "TURNSTILE_SECRET_KEY",
      "TURNSTILE_SITE_KEY",
    ] as const) {
      expect(() =>
        readRuntimeConfig({ ...publicEnv, [binding]: "" }),
      ).toThrow(`Missing required binding: ${binding}`);
    }
  });

  it("exposes only public registration configuration", async () => {
    const inviteResponse = await publicRegistrationRoutes.request(
      "/api/registration/config",
      undefined,
      inviteEnv,
    );
    expect(await inviteResponse.json()).toEqual({
      mode: "invite",
      publicRegistration: null,
    });

    const publicResponse = await publicRegistrationRoutes.request(
      "/api/registration/config",
      undefined,
      publicEnv,
    );
    const body = (await publicResponse.json()) as Record<string, unknown>;
    expect(body).toEqual({
      mode: "public",
      publicRegistration: {
        privacyVersion: "2026-07-17.test",
        siteKey: "test-only-turnstile-site-key",
        termsVersion: "2026-07-17.test",
      },
    });
    expect(JSON.stringify(body)).not.toContain("turnstileSecretKey");
  });

  it("enforces exact origin and issues an intent through the HTTP route", async () => {
    vi.stubGlobal("fetch", verifiedTurnstileFetch);
    const requestBody = JSON.stringify({
      acceptPrivacy: true,
      acceptTerms: true,
      privacyVersion: "2026-07-17.test",
      termsVersion: "2026-07-17.test",
      turnstileToken: "test-route-token",
    });
    const wrongOrigin = await publicRegistrationRoutes.request(
      "/api/registration/intent",
      {
        body: requestBody,
        headers: {
          "content-type": "application/json",
          origin: "https://example.test",
        },
        method: "POST",
      },
      publicEnv,
      testExecutionContext(),
    );
    expect(wrongOrigin.status).toBe(403);
    expect(await wrongOrigin.json()).toEqual({ error: "invalid_origin" });

    const response = await publicRegistrationRoutes.request(
      "/api/registration/intent",
      {
        body: requestBody,
        headers: {
          "cf-connecting-ip": uniqueIp(),
          "content-type": "application/json; charset=utf-8",
          origin: publicConfig.authBaseUrl,
        },
        method: "POST",
      },
      publicEnv,
      testExecutionContext(),
    );
    expect(response.status).toBe(201);
    await expect(response.json()).resolves.toMatchObject({
      expiresAt: expect.any(String),
      intentId: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
    });
  });

  it("rejects content types that only prefix-match application/json", async () => {
    let fetched = false;
    vi.stubGlobal("fetch", async () => {
      fetched = true;
      return Response.json({ success: true });
    });
    const response = await publicRegistrationRoutes.request(
      "/api/registration/intent",
      {
        body: JSON.stringify({
          acceptPrivacy: true,
          acceptTerms: true,
          privacyVersion: "2026-07-17.test",
          termsVersion: "2026-07-17.test",
          turnstileToken: "test-route-token",
        }),
        headers: {
          "cf-connecting-ip": uniqueIp(),
          "content-type": "application/json-evil",
          origin: publicConfig.authBaseUrl,
        },
        method: "POST",
      },
      publicEnv,
      testExecutionContext(),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_registration_intent" });
    expect(fetched).toBe(false);
  });

  it("binds a hashed intent to protected OAuth state and the user hook", async () => {
    const email = randomEmail();
    const intent = await createPublicRegistrationIntent();
    const signInResponse = await worker.fetch(
      new Request("http://localhost:5173/api/registration/social-start", {
        body: JSON.stringify({
          callbackURL: "http://localhost:5173/",
          intentId: intent.intentId,
        }),
        headers: {
          "cf-connecting-ip": uniqueIp(),
          "content-type": "application/json",
          origin: "http://localhost:5173",
        },
        method: "POST",
      }),
      publicEnv,
      testExecutionContext(),
    );
    expect(signInResponse.status).toBe(200);
    const signIn = (await signInResponse.json()) as { url: string };
    const state = new URL(signIn.url).searchParams.get("state");
    const stateCookie = signInResponse.headers.get("set-cookie")?.split(";", 1)[0];
    expect(state).toBeTruthy();
    expect(stateCookie).toBeTruthy();

    const intentHash = await hashPublicRegistrationValue(intent.intentId);
    const storedIntent = await env.PG72_ID_DB.prepare(
      `SELECT intent_hash, oauth_reference_hash, oauth_state_hash
         FROM public_registration_intent
        WHERE intent_hash = ?`,
    )
      .bind(intentHash)
      .first<{
        intent_hash: string;
        oauth_reference_hash: string;
        oauth_state_hash: string;
      }>();
    expect(storedIntent).toMatchObject({
      intent_hash: intentHash,
      oauth_reference_hash: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      oauth_state_hash: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
    });
    expect(JSON.stringify(storedIntent)).not.toContain(intent.intentId);

    const verificationRows = await env.PG72_ID_DB.prepare(
      "SELECT value FROM verification",
    ).all<{ value: string }>();
    expect(verificationRows.results.length).toBeGreaterThan(0);
    expect(JSON.stringify(verificationRows.results)).not.toContain(intent.intentId);

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      expect(String(input)).toBe("https://oauth2.googleapis.com/token");
      return Response.json({
        access_token: "test-google-access-token",
        expires_in: 300,
        id_token: testGoogleIdToken(email),
        token_type: "Bearer",
      });
    });
    const callbackResponse = await worker.fetch(
      new Request(
        `http://localhost:5173/callback/google?code=test-code&state=${encodeURIComponent(state ?? "")}`,
        {
          headers: {
            "cf-connecting-ip": uniqueIp(),
            cookie: stateCookie ?? "",
          },
        },
      ),
      publicEnv,
      testExecutionContext(),
    );
    expect(callbackResponse.status).toBe(302);
    expect(callbackResponse.headers.get("location")).toBe(
      "http://localhost:5173/",
    );

    const user = await env.PG72_ID_DB.prepare(
      `SELECT id, termsAcceptedVersion, privacyAcceptedVersion, legalAcceptedAt
         FROM user
        WHERE email = ?`,
    )
      .bind(email)
      .first<{
        id: string;
        legalAcceptedAt: string;
        privacyAcceptedVersion: string;
        termsAcceptedVersion: string;
      }>();
    expect(user).toMatchObject({
      privacyAcceptedVersion: "2026-07-17.test",
      termsAcceptedVersion: "2026-07-17.test",
    });
    expect(Date.parse(user?.legalAcceptedAt ?? "")).not.toBeNaN();
    const acceptance = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM legal_acceptance WHERE user_id = ?",
    )
      .bind(user?.id)
      .first<{ count: number }>();
    expect(acceptance?.count).toBe(1);
  });

  it("rejects a configured GitHub callback from creating a public user", async () => {
    const email = randomEmail();
    const intent = await createPublicRegistrationIntent();
    const prepared = await preparePublicRegistrationOAuthStart(
      githubPublicEnv,
      readRuntimeConfig(githubPublicEnv),
      intent.intentId,
    );
    const signInResponse = await worker.fetch(
      new Request("http://localhost:5173/sign-in/social", {
        body: JSON.stringify({
          additionalData: {
            [PUBLIC_REGISTRATION_STATE_KEY]: prepared.oauthReference,
          },
          callbackURL: "http://localhost:5173/",
          provider: "github",
          requestSignUp: true,
        }),
        headers: {
          "cf-connecting-ip": uniqueIp(),
          "content-type": "application/json",
          origin: "http://localhost:5173",
        },
        method: "POST",
      }),
      githubPublicEnv,
      testExecutionContext(),
    );
    expect(signInResponse.status).toBe(200);
    const signIn = (await signInResponse.json()) as { url: string };
    const state = new URL(signIn.url).searchParams.get("state");
    const stateCookie = signInResponse.headers.get("set-cookie")?.split(";", 1)[0];
    expect(state).toBeTruthy();
    expect(stateCookie).toBeTruthy();
    await bindPublicRegistrationOAuthState(
      githubPublicEnv,
      readRuntimeConfig(githubPublicEnv),
      prepared,
      state ?? "",
    );

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "https://github.com/login/oauth/access_token") {
        return Response.json({
          access_token: "test-github-access-token",
          scope: "read:user,user:email",
          token_type: "bearer",
        });
      }
      if (url === "https://api.github.com/user") {
        return Response.json({
          avatar_url: null,
          email: null,
          id: 72,
          login: "public-registration-test",
          name: "Public registration test",
        });
      }
      if (url === "https://api.github.com/user/emails") {
        return Response.json([
          { email, primary: true, verified: true, visibility: null },
        ]);
      }
      throw new Error(`Unexpected GitHub request: ${url}`);
    });
    const callbackResponse = await worker.fetch(
      new Request(
        `http://localhost:5173/callback/github?code=test-code&state=${encodeURIComponent(state ?? "")}`,
        {
          headers: {
            "cf-connecting-ip": uniqueIp(),
            cookie: stateCookie ?? "",
          },
        },
      ),
      githubPublicEnv,
      testExecutionContext(),
    );
    expect(callbackResponse.status).toBe(302);
    const errorLocation = callbackResponse.headers.get("location");
    expect(errorLocation).toBeTruthy();
    expect(new URL(errorLocation ?? "http://localhost").pathname).toBe("/error");
    await expect(
      env.PG72_ID_DB.prepare("SELECT COUNT(*) AS count FROM user WHERE email = ?")
        .bind(email)
        .first<number>("count"),
    ).resolves.toBe(0);
  });

  it("widens CSP for Turnstile only in public mode", async () => {
    const inviteResponse = await worker.fetch(
      new Request("http://localhost:5173/health"),
      inviteEnv,
      testExecutionContext(),
    );
    expect(inviteResponse.headers.get("content-security-policy")).not.toContain(
      "challenges.cloudflare.com",
    );

    const publicResponse = await worker.fetch(
      new Request("http://localhost:5173/health"),
      publicEnv,
      testExecutionContext(),
    );
    const csp = publicResponse.headers.get("content-security-policy");
    expect(csp).toContain(
      "script-src 'self' 'nonce-cGc3Mi12aXRlLWRldg==' https://telegram.org https://challenges.cloudflare.com",
    );
    expect(csp).toContain("frame-src https://oauth.telegram.org https://challenges.cloudflare.com");
  });

  it("public mode registers a new verified email without an invitation", async () => {
    const binding = await createPublicRegistrationBinding();
    const grant = await authorizeRegistration(publicEnv, publicConfig, {
      email: randomEmail(),
      emailVerified: true,
      clientIp: uniqueIp(),
      providerId: "google",
      registrationBinding: binding.registrationBinding,
    });

    expect(grant).toMatchObject({
      accessLevel: "restricted",
      privacyAcceptedVersion: "2026-07-17.test",
      role: "user",
      status: "active",
      termsAcceptedVersion: "2026-07-17.test",
    });
    expect(grant.legalAcceptedAt).toBeInstanceOf(Date);
  });

  it("public mode requires a one-time registration intent", async () => {
    await expect(
      authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp: uniqueIp(),
        providerId: "google",
      }),
    ).rejects.toMatchObject({
      body: { code: "REGISTRATION_PREREQUISITE_REQUIRED" },
      statusCode: 403,
    });
  });

  it("rejects a partially bound public registration intent", async () => {
    const intent = await createPublicRegistrationIntent();
    const intentHash = await hashPublicRegistrationValue(intent.intentId);
    await expect(
      env.PG72_ID_DB.prepare(
        `UPDATE public_registration_intent
            SET oauth_reference_hash = ?
          WHERE intent_hash = ?`,
      )
        .bind("A".repeat(43), intentHash)
        .run(),
    ).rejects.toThrow();
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

  it("public mode rejects new users from non-Google social callbacks", async () => {
    const binding = await createPublicRegistrationBinding();
    await expect(
      authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp: uniqueIp(),
        providerId: "github",
        registrationBinding: binding.registrationBinding,
      }),
    ).rejects.toMatchObject({
      body: { code: "REGISTRATION_PREREQUISITE_REQUIRED" },
      statusCode: 403,
    });
  });

  it("public mode still honors a pending invitation's role", async () => {
    const email = randomEmail();
    await createInvitation(email, "admin");
    const binding = await createPublicRegistrationBinding();

    const grant = await authorizeRegistration(publicEnv, publicConfig, {
      email,
      emailVerified: true,
      clientIp: uniqueIp(),
      providerId: "google",
      registrationBinding: binding.registrationBinding,
    });

    expect(grant).toMatchObject({
      accessLevel: "standard",
      role: "admin",
      status: "active",
    });
  });

  it("public mode grants the bootstrap administrator the bootadmin role", async () => {
    const binding = await createPublicRegistrationBinding();
    const grant = await authorizeRegistration(publicEnv, publicConfig, {
      email: env.BOOTSTRAP_ADMIN_EMAIL,
      emailVerified: true,
      clientIp: uniqueIp(),
      providerId: "google",
      registrationBinding: binding.registrationBinding,
    });

    expect(grant).toMatchObject({
      accessLevel: "standard",
      role: "bootadmin",
      status: "active",
    });
  });

  it("rejects a replayed public registration intent", async () => {
    const binding = await createPublicRegistrationBinding();
    await authorizeRegistration(publicEnv, publicConfig, {
      email: randomEmail(),
      emailVerified: true,
      clientIp: uniqueIp(),
      providerId: "google",
      registrationBinding: binding.registrationBinding,
    });

    await expect(
      authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp: uniqueIp(),
        providerId: "google",
        registrationBinding: binding.registrationBinding,
      }),
    ).rejects.toMatchObject({
      body: { code: "REGISTRATION_PREREQUISITE_REQUIRED" },
    });
  });

  it("allows exactly one concurrent claim of a public registration intent", async () => {
    const binding = await createPublicRegistrationBinding();
    const claims = await Promise.allSettled([
      authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp: uniqueIp(),
        providerId: "google",
        registrationBinding: binding.registrationBinding,
      }),
      authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp: uniqueIp(),
        providerId: "google",
        registrationBinding: binding.registrationBinding,
      }),
    ]);

    const winners = claims.filter((claim) => claim.status === "fulfilled");
    const losers = claims.filter((claim) => claim.status === "rejected");
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(1);
    expect(losers[0]).toMatchObject({
      reason: {
        body: { code: "REGISTRATION_PREREQUISITE_REQUIRED" },
        statusCode: 403,
      },
    });
  });

  it("rejects an expired public registration intent", async () => {
    const binding = await createPublicRegistrationBinding();
    await env.PG72_ID_DB.prepare(
      `UPDATE public_registration_intent
          SET created_at = ?, expires_at = ?
        WHERE intent_hash = ?`,
    )
      .bind(
        new Date(Date.now() - 2000).toISOString(),
        new Date(Date.now() - 1000).toISOString(),
        binding.prepared.intentHash,
      )
      .run();

    await expect(
      authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp: uniqueIp(),
        providerId: "google",
        registrationBinding: binding.registrationBinding,
      }),
    ).rejects.toMatchObject({
      body: { code: "REGISTRATION_PREREQUISITE_REQUIRED" },
    });
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
      providerId: "github",
    });

    expect(grant).toEqual({
      accessLevel: "standard",
      role: "user",
      status: "active",
    });
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
      const binding = await createPublicRegistrationBinding(clientIp);
      await authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp,
        providerId: "google",
        registrationBinding: binding.registrationBinding,
      });
    }

    const binding = await createPublicRegistrationBinding(clientIp);
    await expect(
      authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp,
        providerId: "google",
        registrationBinding: binding.registrationBinding,
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
      const binding = await createPublicRegistrationBinding(clientIp);
      await authorizeRegistration(publicEnv, publicConfig, {
        email: randomEmail(),
        emailVerified: true,
        clientIp,
        providerId: "google",
        registrationBinding: binding.registrationBinding,
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

  it("fails closed on wrong legal versions before Turnstile verification", async () => {
    let fetched = false;
    await expect(
      issuePublicRegistrationIntent(
        publicEnv,
        publicConfig,
        {
          acceptPrivacy: true,
          acceptTerms: true,
          privacyVersion: "stale",
          termsVersion: "stale",
          turnstileToken: "not-used",
        },
        uniqueIp(),
        undefined,
        async () => {
          fetched = true;
          return Response.json({ success: true });
        },
      ),
    ).rejects.toMatchObject({ code: "invalid_registration_intent" });
    expect(fetched).toBe(false);
  });

  it("rejects Turnstile hostname and action mismatches", async () => {
    for (const payload of [
      {
        action: TURNSTILE_REGISTRATION_ACTION,
        hostname: "example.test",
        success: true,
      },
      { action: "wrong_action", hostname: "localhost", success: true },
      {
        action: TURNSTILE_REGISTRATION_ACTION,
        hostname: "localhost",
        success: false,
      },
    ]) {
      await expect(
        verifyTurnstileRegistrationToken(
          publicConfig,
          "test-token",
          uniqueIp(),
          async () => Response.json(payload),
        ),
      ).resolves.toEqual({ status: "rejected" });
    }
  });

  it("fails closed when Turnstile verification is unavailable", async () => {
    await expect(
      verifyTurnstileRegistrationToken(
        publicConfig,
        "test-token",
        uniqueIp(),
        async () => {
          throw new Error("network unavailable");
        },
      ),
    ).resolves.toEqual({ status: "unavailable" });
  });

  it("aborts and fails closed when Turnstile verification times out", async () => {
    let aborted = false;
    await expect(
      verifyTurnstileRegistrationToken(
        publicConfig,
        "test-token",
        uniqueIp(),
        async (_input, init) =>
          new Promise<Response>((_resolve, reject) => {
            const signal = init?.signal;
            if (!signal) {
              reject(new Error("missing AbortSignal"));
              return;
            }
            signal.addEventListener(
              "abort",
              () => {
                aborted = true;
                reject(new Error("aborted"));
              },
              { once: true },
            );
          }),
        10,
      ),
    ).resolves.toEqual({ status: "unavailable" });
    expect(aborted).toBe(true);
  });

  it("guards legal history while the account exists and cascades on account deletion", async () => {
    const binding = await createPublicRegistrationBinding();
    const grant = await authorizeRegistration(publicEnv, publicConfig, {
      email: randomEmail(),
      emailVerified: true,
      clientIp: uniqueIp(),
      providerId: "google",
      registrationBinding: binding.registrationBinding,
    });
    const userId = crypto.randomUUID();
    const now = new Date().toISOString();
    await env.PG72_ID_DB.prepare(
      `INSERT INTO user
        (id, name, email, emailVerified, role, status, createdAt, updatedAt,
         termsAcceptedVersion, privacyAcceptedVersion, legalAcceptedAt)
       VALUES (?, 'Public user', ?, 1, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        userId,
        randomEmail(),
        grant.role,
        grant.status,
        now,
        now,
        grant.termsAcceptedVersion,
        grant.privacyAcceptedVersion,
        grant.legalAcceptedAt?.toISOString(),
      )
      .run();

    const acceptance = await env.PG72_ID_DB.prepare(
      `SELECT terms_version, privacy_version, source
         FROM legal_acceptance
        WHERE user_id = ?`,
    )
      .bind(userId)
      .first<{
        privacy_version: string;
        source: string;
        terms_version: string;
      }>();
    expect(acceptance).toEqual({
      privacy_version: "2026-07-17.test",
      source: "public_registration",
      terms_version: "2026-07-17.test",
    });

    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE user SET termsAcceptedVersion = 'changed' WHERE id = ?",
      )
        .bind(userId)
        .run(),
    ).rejects.toThrow();

    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE legal_acceptance SET terms_version = 'changed' WHERE user_id = ?",
      )
        .bind(userId)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.PG72_ID_DB.prepare(
        "DELETE FROM legal_acceptance WHERE user_id = ?",
      )
        .bind(userId)
        .run(),
    ).rejects.toThrow();

    await env.PG72_ID_DB.prepare("DELETE FROM user WHERE id = ?")
      .bind(userId)
      .run();
    await expect(
      env.PG72_ID_DB.prepare(
        "SELECT COUNT(*) AS count FROM legal_acceptance WHERE user_id = ?",
      )
        .bind(userId)
        .first<number>("count"),
    ).resolves.toBe(0);
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
