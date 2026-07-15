import { DatabaseSync } from "node:sqlite";

import { createAuth } from "./auth";

const cliDatabase = new DatabaseSync(":memory:");

const cliEnv = {
  PG72_ID_DB: cliDatabase,
  AUTH_BASE_URL: "http://localhost:5173",
  PASSKEY_RP_ID: "localhost",
  PASSKEY_ORIGIN: "http://localhost:5173",
  REGISTRATION_MODE: "invite",
  ENVIRONMENT: "development",
  BETTER_AUTH_SECRET: "cli-only-placeholder-secret-at-least-32-characters",
  GOOGLE_CLIENT_ID: "cli-placeholder",
  GOOGLE_CLIENT_SECRET: "cli-placeholder",
} as Env;

export const auth = createAuth(cliEnv, undefined, cliDatabase);
