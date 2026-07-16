-- Public registration prerequisites.
--
-- Invite-mode users keep all three user fields NULL. A public registration can
-- set them only during user creation, after a one-time Turnstile-backed intent
-- has been consumed. The acceptance history trigger commits with the user row.

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

CREATE TABLE "public_registration_intent" (
  "id" text NOT NULL PRIMARY KEY,
  "terms_version" text NOT NULL,
  "privacy_version" text NOT NULL,
  "turnstile_hostname" text NOT NULL,
  "turnstile_action" text NOT NULL
    CHECK ("turnstile_action" = 'pgid_public_registration'),
  "created_at" date NOT NULL,
  "expires_at" date NOT NULL,
  "consumed_at" date,
  CHECK (length("id") = 43),
  CHECK (length("terms_version") BETWEEN 1 AND 64),
  CHECK (length("privacy_version") BETWEEN 1 AND 64),
  CHECK (length("turnstile_hostname") BETWEEN 1 AND 253),
  CHECK ("expires_at" > "created_at"),
  CHECK ("consumed_at" IS NULL OR "consumed_at" >= "created_at")
);

CREATE INDEX "public_registration_intent_expiry_idx"
  ON "public_registration_intent" ("expires_at", "consumed_at");

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
