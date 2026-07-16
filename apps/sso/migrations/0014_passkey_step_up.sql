ALTER TABLE "session" ADD COLUMN "passkeyStepUpAt" date;

CREATE TABLE "passkey_step_up_challenge" (
  "id" text NOT NULL PRIMARY KEY,
  "session_id" text NOT NULL UNIQUE
    REFERENCES "session" ("id") ON DELETE CASCADE,
  "user_id" text NOT NULL
    REFERENCES "user" ("id") ON DELETE CASCADE,
  "challenge" text NOT NULL,
  "expires_at" date NOT NULL,
  "created_at" date NOT NULL,
  CHECK (length("challenge") BETWEEN 32 AND 256),
  CHECK ("expires_at" > "created_at")
);

CREATE INDEX "passkey_step_up_challenge_expires_at_idx"
  ON "passkey_step_up_challenge" ("expires_at");
