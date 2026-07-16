import { APIError } from "better-auth/api";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";

import { recordAudit, type WaitUntilContext } from "./audit";
import {
  readRuntimeConfig,
  type PublicRegistrationConfig,
  type RuntimeConfig,
} from "./config";

type AppEnv = { Bindings: Env };

export const PUBLIC_REGISTRATION_STATE_KEY = "pgidRegistrationIntent";
export const TURNSTILE_REGISTRATION_ACTION = "pgid_public_registration";

const TURNSTILE_SITEVERIFY_URL =
  "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const REGISTRATION_INTENT_TTL_MS = 10 * 60 * 1000;
const TURNSTILE_TOKEN_MAX_LENGTH = 2048;
const INTENT_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

interface RegistrationIntentRequest {
  acceptPrivacy?: unknown;
  acceptTerms?: unknown;
  privacyVersion?: unknown;
  termsVersion?: unknown;
  turnstileToken?: unknown;
}

interface RegistrationIntentRow {
  created_at: string;
  privacy_version: string;
  terms_version: string;
}

interface TurnstileSiteverifyPayload {
  action?: unknown;
  hostname?: unknown;
  success?: unknown;
}

export interface ClaimedRegistrationIntent {
  legalAcceptedAt: Date;
  privacyAcceptedVersion: string;
  termsAcceptedVersion: string;
}

type TurnstileVerification =
  | { status: "verified"; hostname: string }
  | { status: "rejected" }
  | { status: "unavailable" };

class RegistrationIntentError extends Error {
  constructor(
    readonly status: 400 | 403 | 429 | 503,
    readonly code: string,
  ) {
    super(code);
  }
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function newIntentId(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function registrationIntentIdFromOAuthState(
  state: unknown,
): string | undefined {
  if (!isRecord(state)) return undefined;
  const value = state[PUBLIC_REGISTRATION_STATE_KEY];
  return typeof value === "string" ? value : undefined;
}

export async function verifyTurnstileRegistrationToken(
  config: RuntimeConfig,
  token: string,
  clientIp: string,
  fetchImpl: typeof fetch = fetch,
): Promise<TurnstileVerification> {
  const registration = config.publicRegistration;
  if (!registration) return { status: "rejected" };

  const body = new FormData();
  body.set("secret", registration.turnstileSecretKey);
  body.set("response", token);
  body.set("idempotency_key", crypto.randomUUID());
  if (clientIp !== "local") body.set("remoteip", clientIp);

  let response: Response;
  try {
    response = await fetchImpl(TURNSTILE_SITEVERIFY_URL, {
      method: "POST",
      body,
    });
  } catch {
    return { status: "unavailable" };
  }

  let payload: TurnstileSiteverifyPayload;
  try {
    const parsed: unknown = await response.json();
    if (!isRecord(parsed)) return { status: "unavailable" };
    payload = parsed;
  } catch {
    return { status: "unavailable" };
  }

  if (!response.ok) return { status: "unavailable" };
  const expectedHostname = new URL(config.authBaseUrl).hostname;
  if (
    payload.success !== true ||
    payload.hostname !== expectedHostname ||
    payload.action !== TURNSTILE_REGISTRATION_ACTION
  ) {
    return { status: "rejected" };
  }

  return { status: "verified", hostname: expectedHostname };
}

function validIntentRequest(
  input: RegistrationIntentRequest | null,
  registration: PublicRegistrationConfig,
): input is Required<RegistrationIntentRequest> & {
  privacyVersion: string;
  termsVersion: string;
  turnstileToken: string;
} {
  return Boolean(
    input &&
      input.acceptPrivacy === true &&
      input.acceptTerms === true &&
      input.privacyVersion === registration.privacyVersion &&
      input.termsVersion === registration.termsVersion &&
      typeof input.turnstileToken === "string" &&
      input.turnstileToken.length > 0 &&
      input.turnstileToken.length <= TURNSTILE_TOKEN_MAX_LENGTH,
  );
}

async function readJson(
  request: Request,
): Promise<RegistrationIntentRequest | null> {
  if (
    !request.headers
      .get("content-type")
      ?.toLowerCase()
      .startsWith("application/json")
  ) {
    return null;
  }
  try {
    const parsed: unknown = await request.json();
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export async function issuePublicRegistrationIntent(
  env: Env,
  config: RuntimeConfig,
  input: RegistrationIntentRequest | null,
  clientIp: string,
  executionCtx?: WaitUntilContext,
  fetchImpl: typeof fetch = fetch,
): Promise<{ expiresAt: string; intentId: string }> {
  const registration = config.publicRegistration;
  if (!registration || !validIntentRequest(input, registration)) {
    throw new RegistrationIntentError(400, "invalid_registration_intent");
  }

  try {
    const rateLimit = await env.AUTH_RATE_LIMITER.limit({
      key: `registration-intent:${clientIp}`,
    });
    if (!rateLimit.success) {
      throw new RegistrationIntentError(429, "registration_rate_limited");
    }
  } catch (error) {
    if (error instanceof RegistrationIntentError) throw error;
    throw new RegistrationIntentError(503, "registration_verification_unavailable");
  }

  const verification = await verifyTurnstileRegistrationToken(
    config,
    input.turnstileToken,
    clientIp,
    fetchImpl,
  );
  if (verification.status !== "verified") {
    await recordAudit(
      env,
      {
        eventType:
          verification.status === "rejected"
            ? "registration.challenge_denied"
            : "registration.challenge_unavailable",
        outcome: verification.status === "rejected" ? "denied" : "failure",
      },
      executionCtx,
    );
    throw new RegistrationIntentError(
      verification.status === "rejected" ? 403 : 503,
      verification.status === "rejected"
        ? "registration_challenge_failed"
        : "registration_verification_unavailable",
    );
  }

  const intentId = newIntentId();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + REGISTRATION_INTENT_TTL_MS);
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `DELETE FROM public_registration_intent
        WHERE expires_at <= ?
           OR consumed_at IS NOT NULL`,
    ).bind(now.toISOString()),
    env.PG72_ID_DB.prepare(
      `INSERT INTO public_registration_intent
        (id, terms_version, privacy_version, turnstile_hostname,
         turnstile_action, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      intentId,
      registration.termsVersion,
      registration.privacyVersion,
      verification.hostname,
      TURNSTILE_REGISTRATION_ACTION,
      now.toISOString(),
      expiresAt.toISOString(),
    ),
  ]);

  await recordAudit(
    env,
    {
      eventType: "registration.intent_created",
      outcome: "success",
      metadata: {
        privacyVersion: registration.privacyVersion,
        termsVersion: registration.termsVersion,
      },
    },
    executionCtx,
  );

  return { expiresAt: expiresAt.toISOString(), intentId };
}

export async function claimPublicRegistrationIntent(
  env: Env,
  config: RuntimeConfig,
  intentId: string | undefined,
  executionCtx?: WaitUntilContext,
): Promise<ClaimedRegistrationIntent> {
  const registration = config.publicRegistration;
  const now = new Date();
  const row =
    registration && intentId && INTENT_ID_PATTERN.test(intentId)
      ? await env.PG72_ID_DB.prepare(
          `UPDATE public_registration_intent
              SET consumed_at = ?
            WHERE id = ?
              AND terms_version = ?
              AND privacy_version = ?
              AND consumed_at IS NULL
              AND expires_at > ?
          RETURNING created_at, terms_version, privacy_version`,
        )
          .bind(
            now.toISOString(),
            intentId,
            registration.termsVersion,
            registration.privacyVersion,
            now.toISOString(),
          )
          .first<RegistrationIntentRow>()
      : null;

  if (!row) {
    await recordAudit(
      env,
      { eventType: "registration.denied", outcome: "denied" },
      executionCtx,
    );
    throw new APIError("FORBIDDEN", {
      code: "REGISTRATION_PREREQUISITE_REQUIRED",
      message: "Complete registration verification before creating an account.",
    });
  }

  return {
    legalAcceptedAt: new Date(row.created_at),
    privacyAcceptedVersion: row.privacy_version,
    termsAcceptedVersion: row.terms_version,
  };
}

export const publicRegistrationRoutes = new Hono<AppEnv>();

publicRegistrationRoutes.use(
  "/api/registration/intent",
  bodyLimit({
    maxSize: 4 * 1024,
    onError: (c) => c.json({ error: "request_too_large" }, 413),
  }),
);

publicRegistrationRoutes.get("/api/registration/config", (c) => {
  const config = readRuntimeConfig(c.env);
  return c.json({
    mode: config.registrationMode,
    publicRegistration: config.publicRegistration
      ? {
          privacyVersion: config.publicRegistration.privacyVersion,
          siteKey: config.publicRegistration.turnstileSiteKey,
          termsVersion: config.publicRegistration.termsVersion,
        }
      : null,
  });
});

publicRegistrationRoutes.post("/api/registration/intent", async (c) => {
  const config = readRuntimeConfig(c.env);
  if (!config.publicRegistration) {
    return c.json({ error: "registration_not_open" }, 403);
  }
  if (c.req.header("origin") !== config.authBaseUrl) {
    return c.json({ error: "invalid_origin" }, 403);
  }

  try {
    const result = await issuePublicRegistrationIntent(
      c.env,
      config,
      await readJson(c.req.raw),
      c.req.header("cf-connecting-ip") ?? "local",
      c.executionCtx,
    );
    return c.json(result, 201);
  } catch (error) {
    if (error instanceof RegistrationIntentError) {
      return c.json({ error: error.code }, error.status);
    }
    throw error;
  }
});
