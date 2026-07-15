import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const copyRoot = fileURLToPath(
  new URL("../../原專案代碼/copy.pg72.tw/", import.meta.url),
);

export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      miniflare: {
        compatibilityDate: "2026-07-14",
        compatibilityFlags: ["nodejs_compat"],
        d1Databases: { DB: "copy-sso-test" },
        bindings: {
          NEXTAUTH_SECRET: "test-nextauth-secret-at-least-32-bytes",
          NEXTAUTH_URL: "https://copy.test",
          PG72_ID_ISSUER: "https://sso.test",
          PG72_ID_CLIENT_ID: "pg72-copy-test",
          PG72_ID_CLIENT_SECRET: "pg72_test_client_secret",
          PG72_TOKEN_VAULT_KEY_V1:
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          TEST_MIGRATIONS: await readD1Migrations(`${copyRoot}/migrations`),
        },
      },
    })),
  ],
  resolve: {
    alias: { "@": copyRoot },
  },
  test: {
    include: ["test/*.spec.ts"],
    setupFiles: ["./test/apply-migrations.ts"],
    testTimeout: 15_000,
  },
});
