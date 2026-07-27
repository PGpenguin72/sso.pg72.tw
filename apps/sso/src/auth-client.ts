import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/react";
import { inferAdditionalFields } from "better-auth/client/plugins";

interface CreatePg72AuthClientOptions {
  baseURL: string;
  customFetchImpl?: typeof fetch;
}

export function createPg72AuthClient({
  baseURL,
  customFetchImpl,
}: CreatePg72AuthClientOptions) {
  return createAuthClient({
    baseURL,
    basePath: "/",
    fetchOptions: {
      credentials: "include",
      ...(customFetchImpl ? { customFetchImpl } : {}),
    },
    plugins: [
      inferAdditionalFields({
        user: {
          accessLevel: {
            type: ["standard", "restricted"],
            required: false,
            defaultValue: "standard",
            input: false,
          },
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
      }),
      passkeyClient(),
      oauthProviderClient(),
    ],
  });
}

export const authClient = createPg72AuthClient({
  baseURL: window.location.origin,
});

export type AuthSession = typeof authClient.$Infer.Session;
