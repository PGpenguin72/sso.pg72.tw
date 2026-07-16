-- Public registration prerequisites.
--
-- Invite-mode users keep all three user fields NULL. A public registration can
-- set them only during user creation, after a one-time Turnstile-backed intent
-- has been consumed. The acceptance history trigger commits with the user row.
-- History is immutable while its parent user exists; deleting the user still
-- removes the account-scoped history through the declared FK cascade.

ALTER TABLE "user" ADD COLUMN "termsAcceptedVersion" text;
ALTER TABLE "user" ADD COLUMN "privacyAcceptedVersion" text;
ALTER TABLE "user" ADD COLUMN "legalAcceptedAt" date;

CREATE TABLE "legal_acceptance" (
  "user_id" text NOT NULL REFERENCES "user" ("id") ON DELETE CASCADE,
  "terms_version" text NOT NULL,
  "privacy_version" text NOT NULL,
  "accepted_at" date NOT NULL,
  "source" text NOT NULL CHECK ("source" = 'public_registration'),
  PRIMARY KEY ("user_id", "terms_version", "privacy_version"),
  CHECK (length("terms_version") BETWEEN 1 AND 64),
  CHECK (length("privacy_version") BETWEEN 1 AND 64)
);

CREATE INDEX "legal_acceptance_time_idx"
  ON "legal_acceptance" ("accepted_at" DESC);

CREATE TRIGGER "legal_acceptance_update_guard"
BEFORE UPDATE ON "legal_acceptance"
BEGIN
  SELECT RAISE(ABORT, 'legal acceptance history is immutable');
END;

CREATE TRIGGER "legal_acceptance_delete_guard"
BEFORE DELETE ON "legal_acceptance"
WHEN EXISTS (
  SELECT 1 FROM "user" WHERE "id" = OLD."user_id"
)
BEGIN
  SELECT RAISE(ABORT, 'legal acceptance history is immutable');
END;

CREATE TABLE "public_registration_intent" (
  "intent_hash" text NOT NULL PRIMARY KEY,
  "terms_version" text NOT NULL,
  "privacy_version" text NOT NULL,
  "turnstile_hostname" text NOT NULL,
  "turnstile_action" text NOT NULL
    CHECK ("turnstile_action" = 'pgid_public_registration'),
  "oauth_reference_hash" text,
  "oauth_state_hash" text,
  "created_at" date NOT NULL,
  "expires_at" date NOT NULL,
  "consumed_at" date,
  CHECK (length("intent_hash") = 43),
  CHECK (length("terms_version") BETWEEN 1 AND 64),
  CHECK (length("privacy_version") BETWEEN 1 AND 64),
  CHECK (length("turnstile_hostname") BETWEEN 1 AND 253),
  CHECK (
    ("oauth_reference_hash" IS NULL AND "oauth_state_hash" IS NULL)
    OR
    (
      "oauth_reference_hash" IS NOT NULL
      AND "oauth_state_hash" IS NOT NULL
      AND length("oauth_reference_hash") = 43
      AND length("oauth_state_hash") = 43
    )
  ),
  CHECK ("expires_at" > "created_at"),
  CHECK ("consumed_at" IS NULL OR "consumed_at" >= "created_at")
);

CREATE INDEX "public_registration_intent_expiry_idx"
  ON "public_registration_intent" ("expires_at", "consumed_at");

CREATE UNIQUE INDEX "public_registration_intent_oauth_reference_idx"
  ON "public_registration_intent" ("oauth_reference_hash")
  WHERE "oauth_reference_hash" IS NOT NULL;

CREATE TRIGGER "user_legal_acceptance_insert_guard"
BEFORE INSERT ON "user"
WHEN
  (NEW."termsAcceptedVersion" IS NULL) !=
    (NEW."privacyAcceptedVersion" IS NULL)
  OR (NEW."termsAcceptedVersion" IS NULL) != (NEW."legalAcceptedAt" IS NULL)
BEGIN
  SELECT RAISE(ABORT, 'legal acceptance fields must be all null or all set');
END;

CREATE TRIGGER "user_legal_acceptance_immutable_guard"
BEFORE UPDATE OF
  "termsAcceptedVersion", "privacyAcceptedVersion", "legalAcceptedAt"
ON "user"
WHEN
  OLD."termsAcceptedVersion" IS NOT NEW."termsAcceptedVersion"
  OR OLD."privacyAcceptedVersion" IS NOT NEW."privacyAcceptedVersion"
  OR OLD."legalAcceptedAt" IS NOT NEW."legalAcceptedAt"
BEGIN
  SELECT RAISE(ABORT, 'initial legal acceptance is immutable');
END;

CREATE TRIGGER "user_legal_acceptance_history"
AFTER INSERT ON "user"
WHEN NEW."termsAcceptedVersion" IS NOT NULL
BEGIN
  INSERT INTO "legal_acceptance"
    ("user_id", "terms_version", "privacy_version", "accepted_at", "source")
  VALUES
    (NEW."id", NEW."termsAcceptedVersion", NEW."privacyAcceptedVersion",
     NEW."legalAcceptedAt", 'public_registration');
END;
