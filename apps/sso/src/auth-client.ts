import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/react";
import { inferAdditionalFields } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: window.location.origin,
  basePath: "/",
  fetchOptions: {
    credentials: "include",
  },
  plugins: [
    inferAdditionalFields({
      user: {
        role: {
          type: ["user", "developer", "admin", "bootadmin"],
          required: false,
          defaultValue: "user",
          input: false,
        },
        status: {
          type: ["active", "suspended", "pending_telegram"],
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

export type AuthSession = typeof authClient.$Infer.Session;
