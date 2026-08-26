import { APIError } from "better-auth/api";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { passkey } from "@better-auth/passkey";

import { recordAudit, type WaitUntilContext } from "./audit";
import { ownedClientShutdownStatements } from "./client-ownership";
import {
  CLIENT_SECRET_PREFIX,
  MAIL_INTROSPECTION_CLIENT_ID,
  TRUSTED_CLIENT_IDS,
  WEBMAIL_CLIENT_ID,
  normalizeEmail,
  readRuntimeConfig,
} from "./config";
import {
  assertSessionUserActive,
  authorizeRegistration,
} from "./registration";
import { effectivePlatformRole, hasPermission } from "./roles";
import { recordLoginAudit, type AuthHookContext } from "./security-activity";

type AuthDatabase = NonNullable<Parameters<typeof betterAuth>[0]["database"]>;

export function createAuth(
  env: Env,
  executionCtx?: WaitUntilContext,
  database: AuthDatabase = env.PG72_ID_DB,
) {
  const config = readRuntimeConfig(env);
  const trustedSocialProviders = [
    "google",
    ...(env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET
      ? ["discord"]
      : []),
    ...(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET ? ["github"] : []),
    ...(env.FACEBOOK_CLIENT_ID && env.FACEBOOK_CLIENT_SECRET
      ? ["facebook"]
      : []),
  ];

  return betterAuth({
    appName: "PGID",
    baseURL: config.authBaseUrl,
    basePath: "/",
    database,
    // `/update-user` and `/unlink-account` are disabled so profile changes and
    // unlinking can only go through the validated, audited first-party routes
    // in worker/account.ts (name normalization, avatar policy, and the
    // "keep at least one sign-in method" rule cannot be bypassed).
    disabledPaths: ["/token", "/update-user", "/unlink-account"],
    secret: env.BETTER_AUTH_SECRET,
    trustedOrigins: [config.authBaseUrl],
    // Google is always on. Discord/GitHub/Facebook/Apple are optional: each is
    // enabled only when its client id and secret are both configured, so a
    // missing social secret never breaks the core Google/Passkey login or
    // fails Worker startup. Telegram is not an OAuth provider and is handled
    // separately in worker/telegram.ts. Implicit account linking stays off, so
    // a matching email cannot silently merge accounts.
    socialProviders: {
      google: {
        clientId: env.GOOGLE_CLIENT_ID,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
        disableIdTokenSignIn: true,
        prompt: "select_account",
      },
      ...(env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET
        ? {
            discord: {
              clientId: env.DISCORD_CLIENT_ID,
              clientSecret: env.DISCORD_CLIENT_SECRET,
            },
          }
        : {}),
      ...(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET
        ? {
            github: {
              clientId: env.GITHUB_CLIENT_ID,
              clientSecret: env.GITHUB_CLIENT_SECRET,
            },
          }
        : {}),
      ...(env.FACEBOOK_CLIENT_ID && env.FACEBOOK_CLIENT_SECRET
        ? {
            facebook: {
              clientId: env.FACEBOOK_CLIENT_ID,
              clientSecret: env.FACEBOOK_CLIENT_SECRET,
            },
          }
        : {}),
      ...(env.APPLE_CLIENT_ID && env.APPLE_CLIENT_SECRET
        ? {
            apple: {
              // Apple's client secret is a short-lived ES256 JWT the operator
              // generates from their Apple private key; PGID reads the current
              // value from the APPLE_CLIENT_SECRET secret and does not mint it.
              clientId: env.APPLE_CLIENT_ID,
              clientSecret: env.APPLE_CLIENT_SECRET,
              ...(env.APPLE_APP_BUNDLE_IDENTIFIER
                ? { appBundleIdentifier: env.APPLE_APP_BUNDLE_IDENTIFIER }
                : {}),
            },
          }
        : {}),
    },
    user: {
      additionalFields: {
        role: {
          type: ["user", "developer", "admin", "bootadmin"],
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
          // OAuth clients owned by the account are preserved but disabled
          // and orphaned before the owner row (and its cascade) goes away.
          await env.PG72_ID_DB.batch(
            ownedClientShutdownStatements(env, user.id, new Date().toISOString()),
          );
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
        trustedProviders: trustedSocialProviders,
        // Explicit linking is initiated from an authenticated PGID session;
        // the provider identity belongs to that session's user even when its
        // email differs. Implicit linking remains disabled above.
        allowDifferentEmails: true,
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
          before: async (user, ctx) => {
            const clientIp =
              ctx?.request?.headers.get("cf-connecting-ip") ??
              ctx?.headers?.get("cf-connecting-ip") ??
              "local";
            const grant = await authorizeRegistration(
              env,
              config,
              {
                email: user.email,
                emailVerified: user.emailVerified === true,
                clientIp,
              },
              executionCtx,
            );
            return { data: { ...user, ...grant } };
          },
          after: async (user) => {
            const email = normalizeEmail(user.email);
            const consumed = await env.PG72_ID_DB.prepare(
              `UPDATE invitation
                  SET consumed_at = ?, consumed_by_user_id = ?
                WHERE email_normalized = ?
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL`,
            )
              .bind(new Date().toISOString(), user.id, email)
              .run();
            const role = typeof user.role === "string" ? user.role : "user";
            await recordAudit(
              env,
              {
                eventType: "user.created",
                outcome: "success",
                subjectId: user.id,
                metadata: {
                  role,
                  roleSource:
                    consumed.meta.changes > 0 ? "invitation" : "default",
                },
              },
              executionCtx,
            );
          },
        },
      },
      account: {
        create: {
          // Fires for the initial sign-up account and for every explicit
          // `/link-social` completion (implicit linking stays disabled).
          after: async (account) => {
            try {
              await recordAudit(
                env,
                {
                  eventType: "account.linked",
                  outcome: "success",
                  subjectId: account.userId,
                },
                executionCtx,
              );
            } catch (error) {
              console.error(
                JSON.stringify({
                  event: "account_link_audit_failed",
                  error: error instanceof Error ? error.name : "UnknownError",
                }),
              );
            }
          },
        },
      },
      session: {
        create: {
          before: async (session) => {
            await assertSessionUserActive(env, config, session.userId);
            return { data: session };
          },
          // Fires for every successful sign-in (Google/social callback or
          // passkey). Records the login with a redacted source summary; the
          // provider is derived from the request path in the hook context.
          after: async (session, context) => {
            await recordLoginAudit(
              env,
              session.userId,
              context as AuthHookContext | undefined,
              executionCtx,
            );
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
        rateLimit: { introspect: false },
        clientPrivileges: ({ user }) =>
          user !== undefined &&
          hasPermission(
            effectivePlatformRole(user.role, user.email, config),
            "clients.manage",
          ),
        prefix: {
          opaqueAccessToken: "pg72_at_",
          refreshToken: "pg72_rt_",
          clientSecret: CLIENT_SECRET_PREFIX,
        },
        customIdTokenClaims: ({ user }) => ({
          "https://pg72.tw/role": effectivePlatformRole(
            user.role,
            user.email,
            config,
          ),
        }),
        authorizeOpaqueAccessTokenIntrospection: ({
          introspectionClientId,
          scopes,
          sessionId,
          tokenClientId,
          user,
        }) =>
          introspectionClientId === MAIL_INTROSPECTION_CLIENT_ID &&
          tokenClientId === WEBMAIL_CLIENT_ID &&
          scopes.includes("email") &&
          typeof sessionId === "string" &&
          user?.emailVerified === true &&
          user.status === "active",
        customAccessTokenClaims: ({ user, scopes }) =>
          user?.emailVerified === true &&
          user.status === "active" &&
          scopes.includes("email")
            ? {
                email: user.email,
                email_verified: true,
              }
            : {},
        customUserInfoClaims: ({ user }) => ({
          "https://pg72.tw/role": effectivePlatformRole(
            user.role,
            user.email,
            config,
          ),
        }),
        advertisedMetadata: {
          claims_supported: [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "sid",
            "acr",
            "scope",
            "azp",
            "name",
            "picture",
            "family_name",
            "given_name",
            "email",
            "email_verified",
            "https://pg72.tw/role",
          ],
        },
      }),
    ],
  });
}

export type Pg72Auth = ReturnType<typeof createAuth>;
