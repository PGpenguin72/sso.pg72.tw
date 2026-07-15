import { APIError } from "better-auth/api";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { passkey } from "@better-auth/passkey";

import { recordAudit, type WaitUntilContext } from "./audit";
import {
  CLIENT_SECRET_PREFIX,
  TRUSTED_CLIENT_IDS,
  normalizeEmail,
  readRuntimeConfig,
} from "./config";

interface InvitationRow {
  id: string;
  role: "admin" | "user";
}

interface StatusRow {
  status: "active" | "suspended";
}

type AuthDatabase = NonNullable<Parameters<typeof betterAuth>[0]["database"]>;

export function createAuth(
  env: Env,
  executionCtx?: WaitUntilContext,
  database: AuthDatabase = env.PG72_ID_DB,
) {
  const config = readRuntimeConfig(env);

  return betterAuth({
    appName: "PGID",
    baseURL: config.authBaseUrl,
    basePath: "/",
    database,
    // `/update-user` is disabled so profile changes can only go through the
    // validated, audited first-party route in worker/account.ts (name
    // normalization and the avatar policy cannot be bypassed).
    disabledPaths: ["/token", "/update-user"],
    secret: env.BETTER_AUTH_SECRET,
    trustedOrigins: [config.authBaseUrl],
    socialProviders: {
      google: {
        clientId: env.GOOGLE_CLIENT_ID,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
        disableIdTokenSignIn: true,
        prompt: "select_account",
      },
    },
    user: {
      additionalFields: {
        role: {
          type: ["user", "admin"],
          required: false,
          defaultValue: "user",
          input: false,
        },
        status: {
          type: ["active", "suspended"],
          required: false,
          defaultValue: "active",
          input: false,
        },
      },
      deleteUser: {
        enabled: true,
        beforeDelete: async (user) => {
          if (normalizeEmail(user.email) === config.bootstrapAdminEmail) {
            await recordAudit(
              env,
              {
                eventType: "account.delete_blocked",
                outcome: "denied",
                subjectId: user.id,
              },
              executionCtx,
            );
            throw new APIError("FORBIDDEN", {
              code: "BOOTSTRAP_ADMIN_PROTECTED",
              message: "The bootstrap administrator account cannot be deleted.",
            });
          }
        },
        afterDelete: async (user) => {
          try {
            await recordAudit(
              env,
              {
                eventType: "account.deleted",
                outcome: "success",
                subjectId: user.id,
              },
              executionCtx,
            );
          } catch (error) {
            console.error(
              JSON.stringify({
                event: "account_delete_audit_failed",
                error: error instanceof Error ? error.name : "UnknownError",
              }),
            );
          }
        },
      },
    },
    session: {
      expiresIn: 60 * 60 * 24 * 30,
      freshAge: 60 * 10,
      updateAge: 60 * 60 * 24,
      cookieCache: { enabled: false },
    },
    account: {
      encryptOAuthTokens: true,
      storeStateStrategy: "database",
      accountLinking: {
        enabled: true,
        disableImplicitLinking: true,
        trustedProviders: [],
        allowDifferentEmails: false,
        allowUnlinkingAll: false,
      },
    },
    verification: {
      storeIdentifier: "hashed",
    },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 100,
      customRules: {
        "/sign-in/social": { window: 60, max: 20 },
        "/passkey/generate-authenticate-options": { window: 60, max: 20 },
        "/passkey/verify-authentication": { window: 60, max: 20 },
      },
    },
    advanced: {
      cookiePrefix: "pg72_id",
      useSecureCookies: config.environment !== "development",
      defaultCookieAttributes: {
        httpOnly: true,
        sameSite: "lax",
        secure: config.environment !== "development",
        path: "/",
      },
      database: {
        generateId: "uuid",
      },
      ipAddress: {
        ipAddressHeaders: ["cf-connecting-ip"],
      },
      backgroundTasks: executionCtx
        ? { handler: (promise) => executionCtx.waitUntil(promise) }
        : undefined,
    },
    databaseHooks: {
      user: {
        create: {
          before: async (user) => {
            const email = normalizeEmail(user.email);
            const isBootstrapAdmin = email === config.bootstrapAdminEmail;

            if (config.registrationMode === "public") {
              return {
                data: {
                  ...user,
                  role: isBootstrapAdmin ? "admin" : "user",
                  status: "active",
                },
              };
            }

            const invitation = await env.PG72_ID_DB.prepare(
              `SELECT id, role
                 FROM invitation
                WHERE email_normalized = ?
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                  AND expires_at > ?
                LIMIT 1`,
            )
              .bind(email, new Date().toISOString())
              .first<InvitationRow>();

            if (!invitation && !isBootstrapAdmin) {
              await recordAudit(
                env,
                { eventType: "registration.denied", outcome: "denied" },
                executionCtx,
              );
              throw new APIError("FORBIDDEN", {
                code: "INVITATION_REQUIRED",
                message: "This PGID account requires an invitation.",
              });
            }

            return {
              data: {
                ...user,
                role: isBootstrapAdmin ? "admin" : (invitation?.role ?? "user"),
                status: "active",
              },
            };
          },
          after: async (user) => {
            const email = normalizeEmail(user.email);
            await env.PG72_ID_DB.prepare(
              `UPDATE invitation
                  SET consumed_at = ?, consumed_by_user_id = ?
                WHERE email_normalized = ?
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL`,
            )
              .bind(new Date().toISOString(), user.id, email)
              .run();
            await recordAudit(
              env,
              {
                eventType: "user.created",
                outcome: "success",
                subjectId: user.id,
              },
              executionCtx,
            );
          },
        },
      },
      session: {
        create: {
          before: async (session) => {
            const user = await env.PG72_ID_DB.prepare(
              "SELECT status FROM user WHERE id = ? LIMIT 1",
            )
              .bind(session.userId)
              .first<StatusRow>();

            if (!user || user.status !== "active") {
              throw new APIError("FORBIDDEN", {
                code: "ACCOUNT_SUSPENDED",
                message: "This account is not allowed to create a session.",
              });
            }
            return { data: session };
          },
        },
      },
    },
    plugins: [
      jwt({
        jwks: {
          jwksPath: "/.well-known/jwks.json",
          rotationInterval: 60 * 60 * 24 * 30,
          gracePeriod: 60 * 60 * 24 * 60,
        },
        jwt: {
          issuer: config.authBaseUrl,
          audience: "https://api.pg72.tw",
          expirationTime: "15m",
        },
      }),
      passkey({
        rpID: config.passkeyRpId,
        rpName: "PGID",
        origin: config.passkeyOrigin,
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "required",
        },
      }),
      oauthProvider({
        loginPage: "/sign-in",
        consentPage: "/consent",
        allowDynamicClientRegistration: false,
        allowUnauthenticatedClientRegistration: false,
        allowPublicClientPrelogin: true,
        cachedTrustedClients: new Set(TRUSTED_CLIENT_IDS),
        scopes: ["openid", "profile", "email", "offline_access"],
        validAudiences: ["https://api.pg72.tw"],
        accessTokenExpiresIn: 60 * 15,
        idTokenExpiresIn: 60 * 10,
        refreshTokenExpiresIn: 60 * 60 * 24 * 30,
        codeExpiresIn: 60,
        clientPrivileges: ({ user }) => user?.role === "admin",
        prefix: {
          opaqueAccessToken: "pg72_at_",
          refreshToken: "pg72_rt_",
          clientSecret: CLIENT_SECRET_PREFIX,
        },
        customIdTokenClaims: ({ user }) => ({
          "https://pg72.tw/role": user.role,
        }),
        customUserInfoClaims: ({ user }) => ({
          "https://pg72.tw/role": user.role,
        }),
        advertisedMetadata: {
          claims_supported: ["https://pg72.tw/role"],
        },
      }),
    ],
  });
}

export type Pg72Auth = ReturnType<typeof createAuth>;
