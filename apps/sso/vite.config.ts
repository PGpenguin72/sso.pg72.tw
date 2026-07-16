import { cloudflare } from "@cloudflare/vite-plugin";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const DEV_CSP_NONCE = "cGc3Mi12aXRlLWRldg==";

// Wrangler filters .dev.vars to configured vars and required secrets when a
// `secrets.required` list exists. Declare optional provider names only for the
// local Vite server so their .dev.vars values remain available without making
// them required (or adding plaintext production vars).
const OPTIONAL_LOCAL_PROVIDER_BINDINGS = {
  APPLE_APP_BUNDLE_IDENTIFIER: "",
  APPLE_CLIENT_ID: "",
  APPLE_CLIENT_SECRET: "",
  DISCORD_CLIENT_ID: "",
  DISCORD_CLIENT_SECRET: "",
  FACEBOOK_CLIENT_ID: "",
  FACEBOOK_CLIENT_SECRET: "",
  GITHUB_CLIENT_ID: "",
  GITHUB_CLIENT_SECRET: "",
  TELEGRAM_BOT_TOKEN: "",
  TELEGRAM_BOT_USERNAME: "",
  PRIVACY_VERSION: "",
  TERMS_VERSION: "",
  TURNSTILE_SECRET_KEY: "",
  TURNSTILE_SITE_KEY: "",
};

export default defineConfig(({ command }) => ({
  html:
    command === "serve"
      ? {
          cspNonce: DEV_CSP_NONCE,
        }
      : undefined,
  plugins: [
    react(),
    cloudflare({
      config:
        command === "serve"
          ? { vars: OPTIONAL_LOCAL_PROVIDER_BINDINGS }
          : undefined,
    }),
  ],
}));
