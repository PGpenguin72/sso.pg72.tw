export type RegistrationMode = "invite" | "public";

/**
 * Plaintext client secrets are issued as `pg72_cs_<suffix>`; the provider
 * strips this prefix before hashing/verification, so the database only stores
 * the SHA-256 (base64url, unpadded) hash of the suffix.
 */
export const CLIENT_SECRET_PREFIX = "pg72_cs_";
export const FRESH_SESSION_MAX_AGE_MS = 10 * 60 * 1000;

/** Fixed clients for the Mail Path A token-introspection trust relationship. */
export const MAIL_INTROSPECTION_CLIENT_ID = "pgid-mail-introspect";
export const WEBMAIL_CLIENT_ID = "pg72-webmail";

/** Client IDs that developers may not claim through the generic client API. */
export const SYSTEM_RESERVED_CLIENT_IDS: ReadonlySet<string> = new Set([
  MAIL_INTROSPECTION_CLIENT_ID,
  WEBMAIL_CLIENT_ID,
]);

/**
 * Clients cached in-memory by the OAuth provider. Their rows must not be
 * mutated at runtime because stale cached copies would keep serving traffic.
 */
export const TRUSTED_CLIENT_IDS: ReadonlySet<string> = new Set(["pg72-test-rp"]);

export interface RuntimeConfig {
  authBaseUrl: string;
  bootstrapAdminEmail: string;
  environment: "development" | "preview" | "production";
  passkeyOrigin: string;
  passkeyRpId: string;
  registrationMode: RegistrationMode;
}

function required(value: string | undefined, name: string): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new Error(`Missing required binding: ${name}`);
  }
  return normalized;
}

function exactOrigin(value: string, name: string): string {
  const url = new URL(value);
  if (url.origin !== value || url.username || url.password) {
    throw new Error(`${name} must be an exact origin without a path`);
  }
  return url.origin;
}

export function readRuntimeConfig(env: Env): RuntimeConfig {
  const registrationMode = required(
    env.REGISTRATION_MODE,
    "REGISTRATION_MODE",
  );
  if (registrationMode !== "invite" && registrationMode !== "public") {
    throw new Error("REGISTRATION_MODE must be invite or public");
  }

  const environment = required(env.ENVIRONMENT, "ENVIRONMENT");
  if (
    environment !== "development" &&
    environment !== "preview" &&
    environment !== "production"
  ) {
    throw new Error("ENVIRONMENT must be development, preview, or production");
  }

  const authBaseUrl = exactOrigin(
    required(env.AUTH_BASE_URL, "AUTH_BASE_URL"),
    "AUTH_BASE_URL",
  );
  const passkeyOrigin = exactOrigin(
    required(env.PASSKEY_ORIGIN, "PASSKEY_ORIGIN"),
    "PASSKEY_ORIGIN",
  );
  const passkeyRpId = required(env.PASSKEY_RP_ID, "PASSKEY_RP_ID");
  const bootstrapAdminEmail = required(
    env.BOOTSTRAP_ADMIN_EMAIL,
    "BOOTSTRAP_ADMIN_EMAIL",
  ).toLowerCase();

  if (environment === "production") {
    if (authBaseUrl !== "https://sso.pg72.tw") {
      throw new Error("Production AUTH_BASE_URL must be https://sso.pg72.tw");
    }
    if (passkeyOrigin !== authBaseUrl || passkeyRpId !== "sso.pg72.tw") {
      throw new Error("Production Passkey origin/RP ID must be sso.pg72.tw");
    }
  }

  return {
    authBaseUrl,
    bootstrapAdminEmail,
    environment,
    passkeyOrigin,
    passkeyRpId,
    registrationMode,
  };
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}
