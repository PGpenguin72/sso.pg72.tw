export type RegistrationMode = "invite" | "public";

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
