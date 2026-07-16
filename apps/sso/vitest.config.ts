import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const TEST_BINDINGS = {
  AUTH_BASE_URL: "http://localhost:5173",
  BETTER_AUTH_SECRET: "test-only-better-auth-secret-0000000000000000",
  BOOTSTRAP_ADMIN_EMAIL: "admin@example.test",
  ENVIRONMENT: "development",
  GOOGLE_CLIENT_ID: "test-only-google-client",
  GOOGLE_CLIENT_SECRET: "test-only-google-secret",
  PASSKEY_ORIGIN: "http://localhost:5173",
  PASSKEY_RP_ID: "localhost",
  PASSKEY_STEP_UP_MAX_AGE_SECONDS: "600",
  REGISTRATION_MODE: "invite",
  // Exercise the custom provider without reading an ignored .dev.vars file.
  TELEGRAM_BOT_TOKEN: "123456:AAvitest-telegram-bot-token",
} as const;

export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          ...TEST_BINDINGS,
          TEST_MIGRATIONS: await readD1Migrations(
            fileURLToPath(new URL("./migrations", import.meta.url)),
          ),
        },
        serviceBindings: {
          ASSETS: () => new Response("asset not found", { status: 404 }),
        },
      },
    })),
  ],
  test: {
    setupFiles: ["./test/apply-migrations.ts"],
    testTimeout: 15_000,
  },
});
