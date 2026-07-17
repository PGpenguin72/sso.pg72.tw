-- Saved recovery codes and the deliberately separate lost-device principal.
-- Existing users receive no rows. RECOVERY_MODE remains the runtime switch.

CREATE TABLE "recovery_code_set" (
  "id" text PRIMARY KEY NOT NULL,
  "user_id" text NOT NULL REFERENCES "user" ("id") ON DELETE CASCADE,
  "generation" integer NOT NULL CHECK ("generation" > 0),
  "format_version" integer NOT NULL DEFAULT 1 CHECK ("format_version" = 1),
  "created_at" date NOT NULL,
  "expires_at" date,
  "revoked_at" date,
  UNIQUE ("user_id", "generation"),
  CHECK (length("id") = 36),
  CHECK ("expires_at" IS NULL OR "expires_at" > "created_at"),
  CHECK ("revoked_at" IS NULL OR "revoked_at" >= "created_at")
);

CREATE UNIQUE INDEX "recovery_code_set_active_user_idx"
  ON "recovery_code_set" ("user_id") WHERE "revoked_at" IS NULL;

CREATE TABLE "recovery_code" (
  "id" text PRIMARY KEY NOT NULL,
  "set_id" text NOT NULL
    REFERENCES "recovery_code_set" ("id") ON DELETE CASCADE,
  "ordinal" integer NOT NULL CHECK ("ordinal" BETWEEN 1 AND 10),
  "code_hash" text NOT NULL UNIQUE,
  "consumed_at" date,
  UNIQUE ("set_id", "ordinal"),
  UNIQUE ("id", "set_id"),
  CHECK (length("id") = 36),
  CHECK (
    length("code_hash") = 43
    AND "code_hash" NOT GLOB '*[^A-Za-z0-9_-]*'
  )
);

CREATE INDEX "recovery_code_remaining_idx"
  ON "recovery_code" ("set_id", "consumed_at");

CREATE TABLE "recovery_session" (
  "id" text PRIMARY KEY NOT NULL,
  "token_hash" text NOT NULL UNIQUE,
  "user_id" text NOT NULL REFERENCES "user" ("id") ON DELETE CASCADE,
  "code_set_id" text NOT NULL
    REFERENCES "recovery_code_set" ("id") ON DELETE CASCADE,
  "source_code_id" text NOT NULL,
  "created_at" date NOT NULL,
  "expires_at" date NOT NULL,
  UNIQUE ("user_id"),
  FOREIGN KEY ("source_code_id", "code_set_id")
    REFERENCES "recovery_code" ("id", "set_id") ON DELETE CASCADE,
  CHECK (length("id") = 36),
  CHECK (
    length("token_hash") = 43
    AND "token_hash" NOT GLOB '*[^A-Za-z0-9_-]*'
  ),
  CHECK (
    unixepoch("expires_at") > unixepoch("created_at")
    AND unixepoch("expires_at") <= unixepoch("created_at") + 600
  )
);

CREATE INDEX "recovery_session_expires_at_idx"
  ON "recovery_session" ("expires_at");

CREATE TABLE "recovery_passkey_challenge" (
  "id" text PRIMARY KEY NOT NULL,
  "recovery_session_id" text NOT NULL UNIQUE
    REFERENCES "recovery_session" ("id") ON DELETE CASCADE,
  "challenge" text NOT NULL,
  "created_at" date NOT NULL,
  "expires_at" date NOT NULL,
  CHECK (length("id") = 36),
  CHECK (length("challenge") BETWEEN 32 AND 256),
  CHECK ("challenge" NOT GLOB '*[^A-Za-z0-9_-]*'),
  CHECK (
    unixepoch("expires_at") > unixepoch("created_at")
    AND unixepoch("expires_at") <= unixepoch("created_at") + 120
  )
);

CREATE INDEX "recovery_passkey_challenge_expires_at_idx"
  ON "recovery_passkey_challenge" ("expires_at");

-- A WebAuthn credential is a globally unique authenticator handle. Recovery
-- must not create a second owner even if a concurrent normal ceremony races.
CREATE UNIQUE INDEX "passkey_credential_id_unique_idx"
  ON "passkey" ("credentialID");

CREATE TRIGGER "recovery_code_set_insert_guard"
BEFORE INSERT ON "recovery_code_set"
WHEN NOT EXISTS (
  SELECT 1 FROM "user"
   WHERE "id" = NEW."user_id" AND "status" = 'active'
)
BEGIN
  SELECT RAISE(ABORT, 'recovery code owner is not active');
END;

CREATE TRIGGER "recovery_code_set_identity_immutable"
BEFORE UPDATE ON "recovery_code_set"
WHEN NEW."id" <> OLD."id"
  OR NEW."user_id" <> OLD."user_id"
  OR NEW."generation" <> OLD."generation"
  OR NEW."format_version" <> OLD."format_version"
  OR NEW."created_at" <> OLD."created_at"
  OR NEW."expires_at" IS NOT OLD."expires_at"
  OR NOT (OLD."revoked_at" IS NULL AND NEW."revoked_at" IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'recovery code set is immutable');
END;

CREATE TRIGGER "recovery_code_set_revoke_cleanup"
AFTER UPDATE OF "revoked_at" ON "recovery_code_set"
WHEN OLD."revoked_at" IS NULL AND NEW."revoked_at" IS NOT NULL
BEGIN
  DELETE FROM "recovery_code" WHERE "set_id" = NEW."id";
END;

CREATE TRIGGER "recovery_code_insert_guard"
BEFORE INSERT ON "recovery_code"
WHEN NEW."consumed_at" IS NOT NULL
  OR NOT EXISTS (
    SELECT 1 FROM "recovery_code_set"
     WHERE "id" = NEW."set_id" AND "revoked_at" IS NULL
  )
BEGIN
  SELECT RAISE(ABORT, 'recovery code set is not active');
END;

CREATE TRIGGER "recovery_code_identity_immutable"
BEFORE UPDATE ON "recovery_code"
WHEN NEW."id" <> OLD."id"
  OR NEW."set_id" <> OLD."set_id"
  OR NEW."ordinal" <> OLD."ordinal"
  OR NEW."code_hash" <> OLD."code_hash"
  OR NOT (OLD."consumed_at" IS NULL AND NEW."consumed_at" IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'recovery code is immutable');
END;

CREATE TRIGGER "recovery_code_consumed_time_guard"
BEFORE UPDATE OF "consumed_at" ON "recovery_code"
WHEN NEW."consumed_at" < (
  SELECT "created_at" FROM "recovery_code_set" WHERE "id" = NEW."set_id"
)
BEGIN
  SELECT RAISE(ABORT, 'recovery code consumption predates its set');
END;

CREATE TRIGGER "recovery_session_insert_guard"
BEFORE INSERT ON "recovery_session"
WHEN NOT EXISTS (
  SELECT 1
    FROM "user" AS u
    JOIN "recovery_code_set" AS s ON s."user_id" = u."id"
    JOIN "recovery_code" AS c ON c."set_id" = s."id"
   WHERE u."id" = NEW."user_id"
     AND u."status" = 'active'
     AND s."id" = NEW."code_set_id"
     AND s."revoked_at" IS NULL
     AND (s."expires_at" IS NULL OR s."expires_at" > NEW."created_at")
     AND c."id" = NEW."source_code_id"
     AND c."consumed_at" IS NOT NULL
     AND c."consumed_at" <= NEW."created_at"
)
BEGIN
  SELECT RAISE(ABORT, 'recovery session source is not eligible');
END;

CREATE TRIGGER "recovery_session_immutable"
BEFORE UPDATE ON "recovery_session"
BEGIN
  SELECT RAISE(ABORT, 'recovery session is immutable');
END;

CREATE TRIGGER "recovery_challenge_immutable"
BEFORE UPDATE ON "recovery_passkey_challenge"
BEGIN
  SELECT RAISE(ABORT, 'recovery challenge is immutable');
END;

CREATE TRIGGER "user_recovery_session_suspension_cleanup"
AFTER UPDATE OF "status" ON "user"
WHEN NEW."status" <> 'active'
BEGIN
  DELETE FROM "recovery_session" WHERE "user_id" = NEW."id";
END;
