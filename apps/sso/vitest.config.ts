import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          TEST_MIGRATIONS: await readD1Migrations(
            fileURLToPath(new URL("./migrations", import.meta.url)),
          ),
          // Deterministic placeholder so the Telegram login provider is
          // exercised in tests regardless of the local .dev.vars.
          TELEGRAM_BOT_TOKEN: "123456:AAvitest-telegram-bot-token",
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
